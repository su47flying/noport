package server

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"noport/pkg"
	"noport/protocol"
)

const httpHandshakeTimeout = 10 * time.Second

// handleHTTPConn handles a single HTTP proxy connection.
// Supports both CONNECT (tunnel) and plain HTTP (forward) methods.
func (s *Server) handleHTTPConn(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr()
	start := time.Now()

	conn.SetDeadline(time.Now().Add(httpHandshakeTimeout))
	br := bufio.NewReader(conn)
	parseStart := time.Now()
	req, err := protocol.ReadHTTPRequest(br)
	if err != nil {
		slog.Debug("http proxy read failed", "remote", remote, "err", err,
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	parseElapsed := time.Since(parseStart)
	conn.SetDeadline(time.Time{})

	target := protocol.HTTPTargetFromRequest(req)
	poolSize, totalStreams := s.dataQueue.Stats()
	slog.Debug("http proxy request", "method", req.Method, "target", target,
		"remote", remote, "pool_size", poolSize, "active_streams", totalStreams,
		"request_parse", parseElapsed.Round(time.Millisecond))

	if req.Method == http.MethodConnect {
		s.handleHTTPConnect(conn, target, remote, parseElapsed, start)
	} else {
		s.handleHTTPPlain(conn, br, req, target, remote, parseElapsed, start)
	}
}

// handleHTTPConnect handles CONNECT method (HTTPS tunneling).
func (s *Server) handleHTTPConnect(conn net.Conn, target string, remote net.Addr, parseElapsed time.Duration, start time.Time) {
	sessionStart := time.Now()
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for http connect", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", time.Since(sessionStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "no tunnel available")
		return
	}
	defer s.dataQueue.CloseSession(session)
	sessionElapsed := time.Since(sessionStart)

	streamStart := time.Now()
	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", time.Since(streamStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "stream open failed")
		return
	}
	defer stream.Close()
	streamElapsed := time.Since(streamStart)

	targetWriteStart := time.Now()
	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", time.Since(targetWriteStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "target write failed")
		return
	}
	targetWriteElapsed := time.Since(targetWriteStart)

	replyStart := time.Now()
	if err := protocol.WriteHTTPConnectOK(conn); err != nil {
		slog.Error("failed to write 200 OK", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", targetWriteElapsed.Round(time.Millisecond),
			"response_write", time.Since(replyStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	responseElapsed := time.Since(replyStart)

	slog.Debug("http connect pipeline ready", "target", target, "remote", remote,
		"request_parse", parseElapsed.Round(time.Millisecond),
		"session_wait", sessionElapsed.Round(time.Millisecond),
		"stream_open", streamElapsed.Round(time.Millisecond),
		"target_write", targetWriteElapsed.Round(time.Millisecond),
		"response_write", responseElapsed.Round(time.Millisecond),
		"setup_total", time.Since(start).Round(time.Millisecond))

	stats := pkg.Relay(conn, stream, &relayBufPool)
	slog.Info("http connect relay done", "target", target,
		"session_id", session.ID(),
		"duration", stats.Duration.Round(time.Millisecond),
		"upload", stats.AToB.Bytes, "download", stats.BToA.Bytes,
		"upload_result", stats.AToB.Result, "download_result", stats.BToA.Result,
		"upload_ttfb", stats.AToB.FirstByte.Round(time.Millisecond),
		"download_ttfb", stats.BToA.FirstByte.Round(time.Millisecond),
		"upload_started", stats.AToB.FirstByteSeen,
		"download_started", stats.BToA.FirstByteSeen)
}

// handleHTTPPlain handles plain HTTP requests (GET, POST, etc.)
// by forwarding through the tunnel.
func (s *Server) handleHTTPPlain(conn net.Conn, br *bufio.Reader, req *http.Request, target string, remote net.Addr, parseElapsed time.Duration, start time.Time) {
	sessionStart := time.Now()
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for http plain", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", time.Since(sessionStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "no tunnel available")
		return
	}
	defer s.dataQueue.CloseSession(session)
	sessionElapsed := time.Since(sessionStart)

	streamStart := time.Now()
	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", time.Since(streamStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "stream open failed")
		return
	}
	defer stream.Close()
	streamElapsed := time.Since(streamStart)

	targetWriteStart := time.Now()
	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", time.Since(targetWriteStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteHTTPError(conn, 502, "target write failed")
		return
	}
	targetWriteElapsed := time.Since(targetWriteStart)

	// Rewrite and send the original HTTP request through the stream
	requestForwardStart := time.Now()
	reqBytes := protocol.RewriteHTTPRequestToRelative(req)
	if _, err := stream.Write(reqBytes); err != nil {
		slog.Error("failed to forward request", "err", err, "target", target, "remote", remote,
			"request_parse", parseElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", targetWriteElapsed.Round(time.Millisecond),
			"request_forward", time.Since(requestForwardStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}

	// Forward request body if present
	if req.Body != nil {
		_, _ = io.Copy(stream, req.Body)
		req.Body.Close()
	}

	// Forward any buffered data that was already read
	if br.Buffered() > 0 {
		peek, _ := br.Peek(br.Buffered())
		_, _ = stream.Write(peek)
	}
	requestForwardElapsed := time.Since(requestForwardStart)

	slog.Debug("http plain pipeline ready", "target", target, "remote", remote,
		"method", req.Method, "path", req.URL.Path,
		"request_parse", parseElapsed.Round(time.Millisecond),
		"session_wait", sessionElapsed.Round(time.Millisecond),
		"stream_open", streamElapsed.Round(time.Millisecond),
		"target_write", targetWriteElapsed.Round(time.Millisecond),
		"request_forward", requestForwardElapsed.Round(time.Millisecond),
		"setup_total", time.Since(start).Round(time.Millisecond))

	// Relay response back: stream → conn, conn → stream
	stats := pkg.Relay(conn, stream, &relayBufPool)
	slog.Info("http plain relay done", "target", target,
		"session_id", session.ID(),
		"method", req.Method, "path", req.URL.Path,
		"duration", stats.Duration.Round(time.Millisecond),
		"upload", stats.AToB.Bytes, "download", stats.BToA.Bytes,
		"upload_result", stats.AToB.Result, "download_result", stats.BToA.Result,
		"upload_ttfb", stats.AToB.FirstByte.Round(time.Millisecond),
		"download_ttfb", stats.BToA.FirstByte.Round(time.Millisecond),
		"upload_started", stats.AToB.FirstByteSeen,
		"download_started", stats.BToA.FirstByteSeen)
}
