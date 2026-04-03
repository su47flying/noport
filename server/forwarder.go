package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"noport/pkg"
	"noport/protocol"
)

const forwarderDialTimeout = 10 * time.Second

// Forwarder listens on -L endpoints and forwards traffic through -F upstream SOCKS5 proxy.
// No tunnel/admin/mux needed — direct TCP forwarding.
type Forwarder struct {
	cfg *pkg.Config
	ctx context.Context
	cancel context.CancelFunc
	wg  sync.WaitGroup

	upstreamAddr string
	upstreamUser string
	upstreamPass string
}

func NewForwarder(cfg *pkg.Config) (*Forwarder, error) {
	fwdEp, ok := pkg.GetEndpoint(cfg.Forwards, "socks5")
	if !ok {
		return nil, fmt.Errorf("no socks5 endpoint in -F flags")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Forwarder{
		cfg:          cfg,
		ctx:          ctx,
		cancel:       cancel,
		upstreamAddr: fmt.Sprintf("%s:%d", fwdEp.Host, fwdEp.Port),
		upstreamUser: fwdEp.User,
		upstreamPass: fwdEp.Pass,
	}, nil
}

func (f *Forwarder) Shutdown() {
	f.cancel()
	f.wg.Wait()
}

func (f *Forwarder) Run() error {
	slog.Info("forwarder starting", "upstream", f.upstreamAddr)

	var numListeners int
	for _, ep := range f.cfg.Listens {
		if ep.Scheme == "socks5" || ep.Scheme == "http" {
			numListeners++
		}
	}
	if numListeners == 0 {
		return fmt.Errorf("no socks5 or http listen endpoints")
	}

	errCh := make(chan error, numListeners)
	f.wg.Add(numListeners)

	for _, ep := range f.cfg.Listens {
		addr := fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		switch ep.Scheme {
		case "socks5":
			user, pass := ep.User, ep.Pass
			go func() {
				defer f.wg.Done()
				if err := f.listenSocks5(addr, user, pass); err != nil {
					slog.Error("forwarder socks5 error", "err", err)
					errCh <- err
				}
			}()
		case "http":
			go func() {
				defer f.wg.Done()
				if err := f.listenHTTP(addr); err != nil {
					slog.Error("forwarder http error", "err", err)
					errCh <- err
				}
			}()
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		slog.Error("fatal error", "err", err)
		f.cancel()
		return err
	case <-f.ctx.Done():
	}

	f.cancel()
	return nil
}

// listenSocks5 accepts SOCKS5 connections and forwards via upstream.
func (f *Forwarder) listenSocks5(addr, user, pass string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()
	slog.Info("forwarder socks5 listener started", "addr", addr)

	go func() { <-f.ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-f.ctx.Done():
				return nil
			default:
				continue
			}
		}
		go f.handleSocks5(conn, user, pass)
	}
}

// listenHTTP accepts HTTP proxy connections and forwards via upstream.
func (f *Forwarder) listenHTTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("http listen: %w", err)
	}
	defer ln.Close()
	slog.Info("forwarder http listener started", "addr", addr)

	go func() { <-f.ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-f.ctx.Done():
				return nil
			default:
				continue
			}
		}
		go f.handleHTTP(conn)
	}
}

// handleSocks5 handles a SOCKS5 client: auth → read CONNECT → dial upstream → SOCKS5 dial → relay.
func (f *Forwarder) handleSocks5(conn net.Conn, user, pass string) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err := protocol.HandleSocks5Handshake(conn, user, pass); err != nil {
		slog.Debug("forwarder socks5 handshake failed", "err", err)
		return
	}

	req, err := protocol.ReadSocks5Request(conn)
	if err != nil {
		protocol.WriteSocks5Reply(conn, protocol.RepCmdNotSupported, nil, 0)
		return
	}
	conn.SetDeadline(time.Time{})

	target := req.Target()
	slog.Debug("forwarder socks5 connect", "target", target)

	upstream, err := f.dialUpstream(target)
	if err != nil {
		slog.Warn("forwarder upstream dial failed", "target", target, "err", err)
		protocol.WriteSocks5Reply(conn, protocol.RepHostUnreach, nil, 0)
		return
	}
	defer upstream.Close()

	protocol.WriteSocks5Reply(conn, protocol.RepSuccess, net.IPv4zero, 0)

	f.relay(conn, upstream, target)
}

// handleHTTP handles an HTTP proxy client: parse request → dial upstream → relay.
func (f *Forwarder) handleHTTP(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(httpHandshakeTimeout))
	br := bufio.NewReader(conn)
	req, err := protocol.ReadHTTPRequest(br)
	if err != nil {
		slog.Debug("forwarder http read failed", "err", err)
		return
	}
	conn.SetDeadline(time.Time{})

	target := protocol.HTTPTargetFromRequest(req)
	slog.Debug("forwarder http request", "method", req.Method, "target", target)

	upstream, err := f.dialUpstream(target)
	if err != nil {
		slog.Warn("forwarder upstream dial failed", "target", target, "err", err)
		protocol.WriteHTTPError(conn, 502, "upstream unavailable")
		return
	}
	defer upstream.Close()

	if req.Method == http.MethodConnect {
		protocol.WriteHTTPConnectOK(conn)
	} else {
		// Forward the original request through upstream
		reqBytes := protocol.RewriteHTTPRequestToRelative(req)
		if _, err := upstream.Write(reqBytes); err != nil {
			slog.Warn("forwarder write request failed", "err", err)
			return
		}
		if req.Body != nil {
			io.Copy(upstream, req.Body)
			req.Body.Close()
		}
		if br.Buffered() > 0 {
			peek, _ := br.Peek(br.Buffered())
			upstream.Write(peek)
		}
	}

	f.relay(conn, upstream, target)
}

// dialUpstream connects to the -F upstream SOCKS5 proxy and issues a CONNECT for the target.
func (f *Forwarder) dialUpstream(target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", f.upstreamAddr, forwarderDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", f.upstreamAddr, err)
	}

	if err := protocol.Socks5Dial(conn, target, f.upstreamUser, f.upstreamPass); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 dial upstream: %w", err)
	}

	return conn, nil
}

// relay copies bidirectionally between two connections (forwarder version).
func (f *Forwarder) relay(left, right net.Conn, target string) {
	start := time.Now()
	var upload, download int64
	done := make(chan struct{})

	go func() {
		buf := relayBufPool.Get().([]byte)
		upload, _ = io.CopyBuffer(right, left, buf)
		relayBufPool.Put(buf)
		if tc, ok := right.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			right.SetReadDeadline(time.Now())
		}
		close(done)
	}()

	buf := relayBufPool.Get().([]byte)
	download, _ = io.CopyBuffer(left, right, buf)
	relayBufPool.Put(buf)
	if tc, ok := left.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		left.SetReadDeadline(time.Now())
	}

	<-done
	slog.Info("forwarder relay done", "target", target,
		"duration", time.Since(start).Round(time.Millisecond),
		"upload", upload, "download", download)
}
