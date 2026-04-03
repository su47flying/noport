package server

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"noport/protocol"
)

const httpHandshakeTimeout = 10 * time.Second

// handleHTTPConn handles a single HTTP proxy connection.
// Supports both CONNECT (tunnel) and plain HTTP (forward) methods.
func (s *Server) handleHTTPConn(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr()

	conn.SetDeadline(time.Now().Add(httpHandshakeTimeout))
	br := bufio.NewReader(conn)
	req, err := protocol.ReadHTTPRequest(br)
	if err != nil {
		slog.Debug("http proxy read failed", "remote", remote, "err", err)
		return
	}
	conn.SetDeadline(time.Time{})

	target := protocol.HTTPTargetFromRequest(req)
	poolSize, totalStreams := s.dataQueue.Stats()
	slog.Debug("http proxy request", "method", req.Method, "target", target,
		"remote", remote, "pool_size", poolSize, "active_streams", totalStreams)

	if req.Method == http.MethodConnect {
		s.handleHTTPConnect(conn, target)
	} else {
		s.handleHTTPPlain(conn, br, req, target)
	}
}

// handleHTTPConnect handles CONNECT method (HTTPS tunneling).
func (s *Server) handleHTTPConnect(conn net.Conn, target string) {
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for http connect", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "no tunnel available")
		return
	}

	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "stream open failed")
		return
	}
	defer stream.Close()

	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "target write failed")
		return
	}

	if err := protocol.WriteHTTPConnectOK(conn); err != nil {
		slog.Error("failed to write 200 OK", "err", err, "target", target)
		return
	}

	stats := relay(conn, stream)
	slog.Info("http connect relay done", "target", target,
		"duration", stats.duration.Round(time.Millisecond),
		"upload", stats.upload, "download", stats.download)
}

// handleHTTPPlain handles plain HTTP requests (GET, POST, etc.)
// by forwarding through the tunnel.
func (s *Server) handleHTTPPlain(conn net.Conn, br *bufio.Reader, req *http.Request, target string) {
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for http plain", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "no tunnel available")
		return
	}

	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "stream open failed")
		return
	}
	defer stream.Close()

	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target", "err", err, "target", target)
		protocol.WriteHTTPError(conn, 502, "target write failed")
		return
	}

	// Rewrite and send the original HTTP request through the stream
	reqBytes := protocol.RewriteHTTPRequestToRelative(req)
	if _, err := stream.Write(reqBytes); err != nil {
		slog.Error("failed to forward request", "err", err, "target", target)
		return
	}

	// Forward request body if present
	if req.Body != nil {
		io.Copy(stream, req.Body)
		req.Body.Close()
	}

	// Forward any buffered data that was already read
	if br.Buffered() > 0 {
		peek, _ := br.Peek(br.Buffered())
		stream.Write(peek)
	}

	// Relay response back: stream → conn, conn → stream
	stats := relay(conn, stream)
	slog.Info("http plain relay done", "target", target,
		"method", req.Method, "path", req.URL.Path,
		"duration", stats.duration.Round(time.Millisecond),
		"upload", stats.upload, "download", stats.download)
}
