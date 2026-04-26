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
	dataSessionWait       = 30 * time.Second
	dataSessionRetryDelay = 250 * time.Millisecond
)

type Server struct {
	cfg          *pkg.Config
	cipher       crypto.Cipher
	adminMu      sync.RWMutex
	adminQueue   *tunnel.AdminQueue
	dataQueue    *tunnel.DataQueue
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	poolSignalMu sync.Mutex
	poolChanged  chan struct{}

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
		cfg:         cfg,
		cipher:      cipher,
		dataQueue:   tunnel.NewDataQueue(cipher, true),
		ctx:         ctx,
		cancel:      cancel,
		poolChanged: make(chan struct{}),
		adminAddr:   fmt.Sprintf("%s:%d", adminEp.Host, adminEp.Port),
		dataAddr:    fmt.Sprintf("%s:%d", dataEp.Host, dataEp.Port),
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
	s.adminMu.RLock()
	adminQueue := s.adminQueue
	s.adminMu.RUnlock()
	if adminQueue != nil {
		adminQueue.Close()
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

		adminQueue := tunnel.NewAdminQueue(conn, func(msg *protocol.AdminMessage) {
			slog.Debug("admin message received", "type", msg.Type)
		})
		if old := s.setAdminQueue(adminQueue); old != nil {
			old.Close()
		}
		s.maintainDataPool("admin_connected")

		// Wait for this admin connection to close, then loop back to accept
		select {
		case <-adminQueue.Done():
			s.clearAdminQueue(adminQueue)
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
		} else {
			s.notifyDataPoolChanged()
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

func (s *Server) setAdminQueue(adminQueue *tunnel.AdminQueue) *tunnel.AdminQueue {
	s.adminMu.Lock()
	old := s.adminQueue
	s.adminQueue = adminQueue
	s.adminMu.Unlock()
	s.notifyDataPoolChanged()
	return old
}

func (s *Server) clearAdminQueue(adminQueue *tunnel.AdminQueue) {
	s.adminMu.Lock()
	if s.adminQueue == adminQueue {
		s.adminQueue = nil
	}
	s.adminMu.Unlock()
	s.notifyDataPoolChanged()
}

func (s *Server) currentAdminQueue() *tunnel.AdminQueue {
	s.adminMu.RLock()
	adminQueue := s.adminQueue
	s.adminMu.RUnlock()
	return adminQueue
}

func (s *Server) notifyDataPoolChanged() {
	s.poolSignalMu.Lock()
	close(s.poolChanged)
	s.poolChanged = make(chan struct{})
	s.poolSignalMu.Unlock()
}

func (s *Server) waitForDataPoolChange(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	s.poolSignalMu.Lock()
	ch := s.poolChanged
	s.poolSignalMu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	case <-s.ctx.Done():
	}
}

// requestDataConns sends CreateDataConn messages to the client via the admin queue.
func (s *Server) requestDataConns(count int) {
	if count <= 0 {
		return
	}
	adminQueue := s.currentAdminQueue()
	if adminQueue == nil {
		slog.Warn("no admin connection, cannot request data conns", "request_count", count)
		return
	}
	for i := 0; i < count; i++ {
		if err := adminQueue.Send(protocol.NewCreateDataConnMsg()); err != nil {
			slog.Error("failed to send CreateDataConn", "err", err)
			return
		}
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
		s.requestDataConns(deficit)
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
	deadline := time.Now().Add(dataSessionWait)
	attempt := 0
	for {
		session, err := s.dataQueue.GetSession()
		if err == nil {
			s.maintainDataPool("checkout")
			return session, nil
		}

		total, idle, busy := s.dataQueue.PoolStats()
		remaining := time.Until(deadline)
		if remaining <= 0 {
			slog.Error("EXHAUSTED: no data connections after wait",
				"pool_size", total,
				"idle", idle,
				"busy", busy,
				"wait", dataSessionWait,
			)
			return nil, fmt.Errorf("no idle data connections available after %s (pool_size=%d idle=%d busy=%d)", dataSessionWait, total, idle, busy)
		}

		attempt++
		if attempt == 1 || attempt%20 == 0 {
			slog.Warn("no idle data session available, waiting for client",
				"attempt", attempt,
				"pool_size", total,
				"idle", idle,
				"busy", busy,
				"wait_remaining", remaining.Round(time.Millisecond),
				"err", err,
			)
		}
		s.maintainDataPool("session_wait")
		wait := dataSessionRetryDelay
		if remaining < wait {
			wait = remaining
		}
		s.waitForDataPoolChange(wait)
	}
}

func (s *Server) retireSession(session *tunnel.MuxSession) {
	s.dataQueue.CloseSession(session)
	s.notifyDataPoolChanged()
	s.maintainDataPool("retire")
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
