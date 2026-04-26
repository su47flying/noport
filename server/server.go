package server

import (
	"context"
	"encoding/binary"
	"fmt"
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
	defaultKey = "noport-default-key"

	// Each proxied request checks out one dedicated data session and retires
	// it when the request finishes. Keep enough idle data connections ready
	// to avoid per-request setup latency, but cap idle sockets so failed or
	// bursty traffic does not grow the pool without bound.
	dataPoolMinIdle       = 8
	dataPoolMaxIdle       = 32
	dataPoolMaintainEvery = 3 * time.Second
	dataSessionMaxRetries = 5
	dataSessionRetryDelay = 500 * time.Millisecond
)

type Server struct {
	cfg        *pkg.Config
	cipher     crypto.Cipher
	adminQueue *tunnel.AdminQueue
	dataQueue  *tunnel.DataQueue
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	adminAddr  string
	dataAddr   string
	socks5Addr string
	socks5User string
	socks5Pass string
	httpAddr   string
}

func New(cfg *pkg.Config) (*Server, error) {
	adminEp, ok := pkg.GetEndpoint(cfg.Remotes, "admin")
	if !ok {
		return nil, fmt.Errorf("no admin endpoint in -R flags")
	}

	// Find the data endpoint (non-admin scheme in Remotes)
	var dataEp pkg.Endpoint
	var foundData bool
	for _, ep := range cfg.Remotes {
		if ep.Scheme != "admin" {
			dataEp = ep
			foundData = true
			break
		}
	}
	if !foundData {
		return nil, fmt.Errorf("no data endpoint in -R flags")
	}

	socks5Ep, hasSocks5 := pkg.GetEndpoint(cfg.Listens, "socks5")
	httpEp, hasHTTP := pkg.GetEndpoint(cfg.Listens, "http")

	if !hasSocks5 && !hasHTTP {
		return nil, fmt.Errorf("no socks5 or http endpoint in -L flags")
	}

	key := []byte(cfg.Key)
	if len(key) == 0 {
		key = []byte(defaultKey)
	}

	cipher, err := crypto.NewCipher(dataEp.Scheme, key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	srv := &Server{
		cfg:       cfg,
		cipher:    cipher,
		dataQueue: tunnel.NewDataQueue(cipher, true),
		ctx:       ctx,
		cancel:    cancel,
		adminAddr: fmt.Sprintf("%s:%d", adminEp.Host, adminEp.Port),
		dataAddr:  fmt.Sprintf("%s:%d", dataEp.Host, dataEp.Port),
	}

	if hasSocks5 {
		srv.socks5Addr = fmt.Sprintf("%s:%d", socks5Ep.Host, socks5Ep.Port)
		srv.socks5User = socks5Ep.User
		srv.socks5Pass = socks5Ep.Pass
	}
	if hasHTTP {
		srv.httpAddr = fmt.Sprintf("%s:%d", httpEp.Host, httpEp.Port)
	}

	return srv, nil
}

func (s *Server) Run() error {
	slog.Info("server starting",
		"admin", s.adminAddr,
		"data", s.dataAddr,
		"socks5", s.socks5Addr,
		"http", s.httpAddr,
		"cipher", s.cipher.Name(),
	)

	// Count listeners: admin + data + optional socks5 + optional http
	numListeners := 2
	if s.socks5Addr != "" {
		numListeners++
	}
	if s.httpAddr != "" {
		numListeners++
	}

	errCh := make(chan error, numListeners)

	s.wg.Add(numListeners)
	go func() {
		defer s.wg.Done()
		if err := s.listenAdmin(s.adminAddr); err != nil {
			slog.Error("admin listener error", "err", err)
			errCh <- err
		}
	}()
	go func() {
		defer s.wg.Done()
		if err := s.listenData(s.dataAddr); err != nil {
			slog.Error("data listener error", "err", err)
			errCh <- err
		}
	}()
	if s.socks5Addr != "" {
		go func() {
			defer s.wg.Done()
			if err := s.listenSocks5(s.socks5Addr); err != nil {
				slog.Error("socks5 listener error", "err", err)
				errCh <- err
			}
		}()
	}
	if s.httpAddr != "" {
		go func() {
			defer s.wg.Done()
			if err := s.listenHTTP(s.httpAddr); err != nil {
				slog.Error("http listener error", "err", err)
				errCh <- err
			}
		}()
	}

	// Wait for shutdown signal or fatal error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		slog.Error("fatal error, shutting down", "err", err)
		s.Shutdown()
		return err
	case <-s.ctx.Done():
	}

	s.Shutdown()
	return nil
}

func (s *Server) Shutdown() {
	s.cancel()
	if s.adminQueue != nil {
		s.adminQueue.Close()
	}
	s.dataQueue.Close()
}

func (s *Server) listenAdmin(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listen: %w", err)
	}
	defer ln.Close()

	slog.Info("admin listener started", "addr", addr)

	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				slog.Warn("admin accept error", "err", err)
				continue
			}
		}

		slog.Info("admin client connected", "remote", conn.RemoteAddr())

		// Close previous admin queue if exists
		if s.adminQueue != nil {
			s.adminQueue.Close()
		}

		s.adminQueue = tunnel.NewAdminQueue(conn, func(msg *protocol.AdminMessage) {
			slog.Debug("admin message received", "type", msg.Type)
		})

		// Wait for this admin connection to close, then loop back to accept
		select {
		case <-s.adminQueue.Done():
			slog.Info("admin connection closed, waiting for reconnect")
		case <-s.ctx.Done():
			return nil
		}
	}
}

func (s *Server) listenData(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("data listen: %w", err)
	}
	defer ln.Close()

	slog.Info("data listener started", "addr", addr)

	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	// Periodic session distribution logging and idle-pool maintenance.
	go func() {
		ticker := time.NewTicker(dataPoolMaintainEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.maintainDataPool("periodic")
				total, idle, busy := s.dataQueue.PoolStats()
				infos := s.dataQueue.DetailedStats()
				dist := make([]string, len(infos))
				for i, info := range infos {
					state := "busy"
					if info.Idle {
						state = "idle"
					}
					if info.Closed {
						state = "closed"
					}
					dist[i] = fmt.Sprintf("s%d:%d/%s", info.ID, info.Streams, state)
				}
				slog.Debug("data pool status",
					"pool_size", total,
					"idle", idle,
					"busy", busy,
					"distribution", dist,
				)
			case <-s.ctx.Done():
				return
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				slog.Warn("data accept error", "err", err)
				continue
			}
		}

		slog.Info("data connection added", "remote", conn.RemoteAddr())
		if _, err := s.dataQueue.AddConn(conn); err != nil {
			slog.Error("failed to add data connection", "err", err)
			conn.Close()
		}
	}
}

func (s *Server) listenSocks5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()

	slog.Info("socks5 listener started", "addr", addr)

	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				slog.Warn("socks5 accept error", "err", err)
				continue
			}
		}

		slog.Debug("socks5 connection accepted", "remote", conn.RemoteAddr())
		go s.handleSocks5Conn(conn)
	}
}

func (s *Server) listenHTTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	defer ln.Close()

	slog.Info("http proxy listener started", "addr", addr)

	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				slog.Warn("http accept error", "err", err)
				continue
			}
		}

		slog.Debug("http connection accepted", "remote", conn.RemoteAddr())
		go s.handleHTTPConn(conn)
	}
}

// requestDataConn sends a CreateDataConn message to the client via admin queue.
func (s *Server) requestDataConn() {
	if s.adminQueue == nil {
		slog.Warn("no admin connection, cannot request data conn")
		return
	}
	msg := protocol.NewCreateDataConnMsg()
	if err := s.adminQueue.Send(msg); err != nil {
		slog.Error("failed to send CreateDataConn", "err", err)
	}
}

// maintainDataPool keeps the idle data-connection pool between configured
// bounds. Busy sessions are never closed; excess idle sessions are trimmed.
func (s *Server) maintainDataPool(reason string) {
	total, idle, busy := s.dataQueue.PoolStats()
	if idle < dataPoolMinIdle {
		deficit := dataPoolMinIdle - idle
		slog.Debug("data pool below idle minimum, requesting connections",
			"reason", reason,
			"total", total,
			"idle", idle,
			"busy", busy,
			"min_idle", dataPoolMinIdle,
			"request_count", deficit,
		)
		for i := 0; i < deficit; i++ {
			s.requestDataConn()
		}
	}

	if idle > dataPoolMaxIdle {
		closed := s.dataQueue.CloseIdleExcess(dataPoolMaxIdle)
		if closed > 0 {
			slog.Info("trimmed excess idle data connections",
				"reason", reason,
				"idle_before", idle,
				"max_idle", dataPoolMaxIdle,
				"closed", closed,
			)
		}
	}
}

// getSessionWithRetry checks out one idle mux session exclusively for one
// proxied request. The caller must retire it with dataQueue.CloseSession
// when the request completes; sessions are intentionally not reused.
func (s *Server) getSessionWithRetry() (*tunnel.MuxSession, error) {
	for i := 0; i < dataSessionMaxRetries; i++ {
		session, err := s.dataQueue.GetSession()
		if err == nil {
			s.maintainDataPool("checkout")
			return session, nil
		}

		total, idle, busy := s.dataQueue.PoolStats()
		slog.Warn("no data session available, requesting from client",
			"attempt", i+1,
			"max_retries", dataSessionMaxRetries,
			"pool_size", total,
			"idle", idle,
			"busy", busy,
			"err", err,
		)
		s.requestDataConn()
		time.Sleep(dataSessionRetryDelay)
	}

	total, idle, busy := s.dataQueue.PoolStats()
	slog.Error("EXHAUSTED: no data connections after all retries",
		"pool_size", total,
		"idle", idle,
		"busy", busy,
	)
	return nil, fmt.Errorf("no idle data connections available after retries (pool_size=%d idle=%d busy=%d)", total, idle, busy)
}

// writeTargetToStream writes the target address as a length-prefixed string
// to the mux stream: [2 byte big-endian length][target bytes]
func writeTargetToStream(stream net.Conn, target string) error {
	targetBytes := []byte(target)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(targetBytes)))

	if _, err := stream.Write(lenBuf); err != nil {
		return fmt.Errorf("writing target length: %w", err)
	}
	if _, err := stream.Write(targetBytes); err != nil {
		return fmt.Errorf("writing target: %w", err)
	}
	return nil
}
