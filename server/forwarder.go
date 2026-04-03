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
	cfg    *pkg.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	upstreamAddr string
	upstreamUser string
	upstreamPass string
}

type upstreamDialStats struct {
	TCPDial time.Duration
	Socks5  time.Duration
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
	start := time.Now()

	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	handshakeStart := time.Now()
	if err := protocol.HandleSocks5Handshake(conn, user, pass); err != nil {
		slog.Debug("forwarder socks5 handshake failed", "err", err,
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	handshakeElapsed := time.Since(handshakeStart)

	requestStart := time.Now()
	req, err := protocol.ReadSocks5Request(conn)
	if err != nil {
		protocol.WriteSocks5Reply(conn, protocol.RepCmdNotSupported, nil, 0)
		return
	}
	requestElapsed := time.Since(requestStart)
	conn.SetDeadline(time.Time{})

	target := req.Target()
	slog.Debug("forwarder socks5 connect", "target", target)

	upstream, dialStats, err := f.dialUpstream(target)
	if err != nil {
		slog.Warn("forwarder upstream dial failed", "target", target, "err", err,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
			"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteSocks5Reply(conn, protocol.RepHostUnreach, nil, 0)
		return
	}
	defer upstream.Close()

	replyStart := time.Now()
	if err := protocol.WriteSocks5Reply(conn, protocol.RepSuccess, net.IPv4zero, 0); err != nil {
		slog.Warn("forwarder write socks5 reply failed", "target", target, "err", err,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
			"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
			"reply_write", time.Since(replyStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	replyElapsed := time.Since(replyStart)

	slog.Debug("forwarder socks5 pipeline ready", "target", target,
		"handshake", handshakeElapsed.Round(time.Millisecond),
		"request_read", requestElapsed.Round(time.Millisecond),
		"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
		"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
		"reply_write", replyElapsed.Round(time.Millisecond),
		"setup_total", time.Since(start).Round(time.Millisecond))

	f.relay(conn, upstream, target)
}

// handleHTTP handles an HTTP proxy client: parse request → dial upstream → relay.
func (f *Forwarder) handleHTTP(conn net.Conn) {
	defer conn.Close()
	start := time.Now()

	conn.SetDeadline(time.Now().Add(httpHandshakeTimeout))
	br := bufio.NewReader(conn)
	parseStart := time.Now()
	req, err := protocol.ReadHTTPRequest(br)
	if err != nil {
		slog.Debug("forwarder http read failed", "err", err,
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	parseElapsed := time.Since(parseStart)
	conn.SetDeadline(time.Time{})

	target := protocol.HTTPTargetFromRequest(req)
	slog.Debug("forwarder http request", "method", req.Method, "target", target,
		"request_parse", parseElapsed.Round(time.Millisecond))

	upstream, dialStats, err := f.dialUpstream(target)
	if err != nil {
		slog.Warn("forwarder upstream dial failed", "target", target, "err", err,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
			"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "upstream unavailable")
		return
	}
	defer upstream.Close()

	if req.Method == http.MethodConnect {
		replyStart := time.Now()
		if err := protocol.WriteHTTPConnectOK(conn); err != nil {
			slog.Warn("forwarder write connect ok failed", "target", target, "err", err,
				"request_parse", parseElapsed.Round(time.Millisecond),
				"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
				"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
				"response_write", time.Since(replyStart).Round(time.Millisecond),
				"elapsed", time.Since(start).Round(time.Millisecond))
			return
		}
		slog.Debug("forwarder http connect pipeline ready", "target", target,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
			"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
			"response_write", time.Since(replyStart).Round(time.Millisecond),
			"setup_total", time.Since(start).Round(time.Millisecond))
	} else {
		// Forward the original request through upstream
		requestForwardStart := time.Now()
		reqBytes := protocol.RewriteHTTPRequestToRelative(req)
		if _, err := upstream.Write(reqBytes); err != nil {
			slog.Warn("forwarder write request failed", "err", err)
			return
		}
		if req.Body != nil {
			_, _ = io.Copy(upstream, req.Body)
			req.Body.Close()
		}
		if br.Buffered() > 0 {
			peek, _ := br.Peek(br.Buffered())
			_, _ = upstream.Write(peek)
		}
		slog.Debug("forwarder http plain pipeline ready", "target", target,
			"method", req.Method,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"upstream_tcp_dial", dialStats.TCPDial.Round(time.Millisecond),
			"upstream_socks5", dialStats.Socks5.Round(time.Millisecond),
			"request_forward", time.Since(requestForwardStart).Round(time.Millisecond),
			"setup_total", time.Since(start).Round(time.Millisecond))
	}

	f.relay(conn, upstream, target)
}

// dialUpstream connects to the -F upstream SOCKS5 proxy and issues a CONNECT for the target.
func (f *Forwarder) dialUpstream(target string) (net.Conn, upstreamDialStats, error) {
	var stats upstreamDialStats
	dialStart := time.Now()
	conn, err := net.DialTimeout("tcp", f.upstreamAddr, forwarderDialTimeout)
	if err != nil {
		stats.TCPDial = time.Since(dialStart)
		return nil, stats, fmt.Errorf("dial upstream %s: %w", f.upstreamAddr, err)
	}
	stats.TCPDial = time.Since(dialStart)

	socksStart := time.Now()
	if err := protocol.Socks5Dial(conn, target, f.upstreamUser, f.upstreamPass); err != nil {
		stats.Socks5 = time.Since(socksStart)
		conn.Close()
		return nil, stats, fmt.Errorf("socks5 dial upstream: %w", err)
	}
	stats.Socks5 = time.Since(socksStart)

	return conn, stats, nil
}

// relay copies bidirectionally between two connections (forwarder version).
func (f *Forwarder) relay(left, right net.Conn, target string) {
	stats := pkg.Relay(left, right, &relayBufPool)
	slog.Info("forwarder relay done", "target", target,
		"duration", stats.Duration.Round(time.Millisecond),
		"upload", stats.AToB.Bytes, "download", stats.BToA.Bytes,
		"upload_result", stats.AToB.Result, "download_result", stats.BToA.Result,
		"upload_ttfb", stats.AToB.FirstByte.Round(time.Millisecond),
		"download_ttfb", stats.BToA.FirstByte.Round(time.Millisecond),
		"upload_started", stats.AToB.FirstByteSeen,
		"download_started", stats.BToA.FirstByteSeen)
}
