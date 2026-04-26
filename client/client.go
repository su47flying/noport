package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"noport/crypto"
	"noport/pkg"
	"noport/protocol"
	"noport/tunnel"
)

const (
	initialDataConns = 10
	minDataConns     = 5
	dialTimeout      = 10 * time.Second
)

type Client struct {
	cfg        *pkg.Config
	cipher     crypto.Cipher
	adminAddr  string
	dataAddr   string
	adminQueue *tunnel.AdminQueue
	dataQueue  *tunnel.DataQueue
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func New(cfg *pkg.Config) (*Client, error) {
	adminEp, ok := pkg.GetEndpoint(cfg.Connects, "admin")
	if !ok {
		return nil, fmt.Errorf("no admin endpoint in -C flags")
	}

	// Find first non-admin endpoint for data connection
	var dataEp pkg.Endpoint
	found := false
	for _, ep := range cfg.Connects {
		if ep.Scheme != "admin" {
			dataEp = ep
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no data endpoint in -C flags")
	}

	key := cfg.Key
	if key == "" {
		key = "noport-default-key"
	}

	cipher, err := crypto.NewCipher(dataEp.Scheme, []byte(key))
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		cfg:       cfg,
		cipher:    cipher,
		adminAddr: fmt.Sprintf("%s:%d", adminEp.Host, adminEp.Port),
		dataAddr:  fmt.Sprintf("%s:%d", dataEp.Host, dataEp.Port),
		dataQueue: tunnel.NewDataQueue(cipher, false),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func (c *Client) Run() error {
	if err := c.connectAdmin(); err != nil {
		return fmt.Errorf("connect admin: %w", err)
	}
	slog.Info("admin connected", "addr", c.adminAddr)

	for i := 0; i < initialDataConns; i++ {
		if err := c.connectData(); err != nil {
			slog.Error("initial data connection failed", "err", err, "index", i)
		}
	}
	slog.Info("data connections established", "count", c.dataQueue.Size())

	for _, session := range c.dataQueue.Sessions() {
		c.wg.Add(1)
		go func(s *tunnel.MuxSession) {
			defer c.wg.Done()
			c.serveSession(s)
		}(session)
	}

	// Monitor admin queue and reconnect on disconnect
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.adminQueue.Done():
				slog.Warn("admin connection lost, reconnecting...")
				err := pkg.Reconnect(c.ctx, "admin", func() error {
					return c.connectAdmin()
				})
				if err != nil {
					slog.Error("admin reconnect failed", "err", err)
					c.cancel()
					return
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()

	// Monitor data connection pool health
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.monitorDataConns()
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received signal", "signal", sig)
	case <-c.ctx.Done():
	}

	c.Shutdown()
	return nil
}

func (c *Client) Shutdown() {
	c.cancel()
	if c.adminQueue != nil {
		c.adminQueue.Close()
	}
	c.dataQueue.Close()
	c.wg.Wait()
	slog.Info("client shut down")
}

func (c *Client) connectAdmin() error {
	conn, err := net.DialTimeout("tcp", c.adminAddr, dialTimeout)
	if err != nil {
		return err
	}
	c.adminQueue = tunnel.NewAdminQueue(conn, c.onAdminMessage)
	return nil
}

func (c *Client) connectData() error {
	conn, err := net.DialTimeout("tcp", c.dataAddr, dialTimeout)
	if err != nil {
		return fmt.Errorf("dial data: %w", err)
	}
	pkg.TuneDataConn(conn)

	session, err := c.dataQueue.AddConn(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("add conn: %w", err)
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.serveSession(session)
	}()

	slog.Info("data connection added", "addr", c.dataAddr, "pool_size", c.dataQueue.Size())
	return nil
}

func (c *Client) onAdminMessage(msg *protocol.AdminMessage) {
	switch msg.Type {
	case protocol.MsgCreateDataConn:
		slog.Debug("received CreateDataConn request")
		go func() {
			if err := c.connectData(); err != nil {
				slog.Error("connectData on admin request failed", "err", err)
			}
		}()
	case protocol.MsgClose:
		slog.Info("received close from server")
		c.Shutdown()
	default:
		slog.Warn("unknown admin message type", "type", msg.Type)
	}
}

// monitorDataConns periodically checks pool size and replenishes if needed.
func (c *Client) monitorDataConns() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			poolSize, totalStreams := c.dataQueue.Stats()
			if poolSize < minDataConns {
				slog.Warn("data pool below minimum, adding connections",
					"current", poolSize, "min", minDataConns, "active_streams", totalStreams)
				for i := poolSize; i < initialDataConns; i++ {
					if err := c.connectData(); err != nil {
						slog.Warn("failed to replenish data connection", "err", err)
					}
				}
			} else {
				infos := c.dataQueue.DetailedStats()
				dist := make([]string, len(infos))
				for i, info := range infos {
					dist[i] = fmt.Sprintf("s%d:%d/%dKB", info.ID, info.Streams, info.Inflight/1024)
				}
				slog.Debug("data pool status",
					"pool_size", poolSize,
					"total_streams", totalStreams,
					"distribution", dist,
				)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) serveSession(session *tunnel.MuxSession) {
	for {
		stream, err := session.Accept()
		if err != nil {
			slog.Debug("session accept error", "err", err)
			c.dataQueue.RemoveSession(session)
			return
		}
		go c.handleStream(stream)
	}
}

func (c *Client) handleStream(stream *tunnel.MuxStream) {
	defer stream.Close()
	start := time.Now()

	// Read 2-byte target address length (big-endian)
	var addrLen uint16
	targetReadStart := time.Now()
	if err := binary.Read(stream, binary.BigEndian, &addrLen); err != nil {
		slog.Debug("read addr length failed", "err", err)
		return
	}

	// Read target address
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		slog.Debug("read addr failed", "err", err)
		return
	}
	target := string(addrBuf)
	targetReadElapsed := time.Since(targetReadStart)

	// Dial the actual target (no success byte — server already told APP "OK").
	// Any data APP sends during dial is buffered in MuxStream's bytes.Buffer.
	dialStart := time.Now()
	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		slog.Warn("dial target failed", "target", target, "err", err,
			"target_read", targetReadElapsed.Round(time.Millisecond),
			"dial_target", time.Since(dialStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		return // stream.Close() via defer will notify server
	}
	defer targetConn.Close()
	dialElapsed := time.Since(dialStart)

	slog.Debug("client stream ready", "target", target,
		"target_read", targetReadElapsed.Round(time.Millisecond),
		"dial_target", dialElapsed.Round(time.Millisecond),
		"setup_total", time.Since(start).Round(time.Millisecond))

	// relay returns (fromB, fromA) where a=stream, b=targetConn:
	//   fromB = bytes from targetConn written to stream (target response)
	//   fromA = bytes from stream written to targetConn (data forwarded to target)
	relayStart := time.Now()
	stats := pkg.Relay(stream, targetConn, &relayBufPool)
	slog.Info("relay done", "target", target,
		"duration", time.Since(relayStart).Round(time.Millisecond),
		"to_target", stats.AToB.Bytes,
		"from_target", stats.BToA.Bytes,
		"to_target_result", stats.AToB.Result,
		"from_target_result", stats.BToA.Result,
		"to_target_ttfb", stats.AToB.FirstByte.Round(time.Millisecond),
		"from_target_ttfb", stats.BToA.FirstByte.Round(time.Millisecond),
		"to_target_started", stats.AToB.FirstByteSeen,
		"from_target_started", stats.BToA.FirstByteSeen,
	)
}
