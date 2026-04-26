package server

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"noport/pkg"
	"noport/protocol"
)

const (
	socks5HandshakeTimeout = 10 * time.Second
	relayBufSize           = 128 << 10 // 128KB
)

var relayBufPool = sync.Pool{
	New: func() any { return make([]byte, relayBufSize) },
}

// handleSocks5Conn handles a single SOCKS5 connection.
func (s *Server) handleSocks5Conn(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr()
	start := time.Now()

	// Step 1: SOCKS5 handshake (with timeout)
	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	handshakeStart := time.Now()
	if err := protocol.HandleSocks5Handshake(conn, s.socks5User, s.socks5Pass); err != nil {
		slog.Debug("socks5 handshake failed", "remote", remote, "err", err,
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	handshakeElapsed := time.Since(handshakeStart)

	// Step 2: Read CONNECT request
	requestStart := time.Now()
	req, err := protocol.ReadSocks5Request(conn)
	if err != nil {
		slog.Debug("socks5 request failed", "remote", remote, "err", err,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteSocks5Reply(conn, protocol.RepCmdNotSupported, nil, 0)
		return
	}
	requestElapsed := time.Since(requestStart)
	// Clear deadline after handshake/request phase
	conn.SetDeadline(time.Time{})

	target := req.Target()
	poolSize, totalStreams := s.dataQueue.Stats()
	slog.Debug("socks5 connect", "target", target, "remote", remote,
		"pool_size", poolSize, "active_streams", totalStreams)

	// Step 3: Get a MuxSession from data queue (with retry)
	sessionStart := time.Now()
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for socks5", "err", err, "target", target, "remote", remote,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"session_wait", time.Since(sessionStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}
	defer s.dataQueue.CloseSession(session)
	sessionElapsed := time.Since(sessionStart)

	// Step 4: Open a mux stream
	streamStart := time.Now()
	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target,
			"pool_size", s.dataQueue.Size(), "session_streams", session.NumStreams(),
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", time.Since(streamStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}
	defer stream.Close()
	streamElapsed := time.Since(streamStart)

	// Step 5: Send target address through the stream (length-prefixed)
	targetWriteStart := time.Now()
	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target to stream", "err", err, "target", target,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", time.Since(targetWriteStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}
	targetWriteElapsed := time.Since(targetWriteStart)

	// Step 6: Send SOCKS5 success reply immediately (optimistic, no round-trip wait).
	// Client will dial target and start relay in parallel. If client can't connect,
	// it closes the stream and the relay terminates — APP sees a broken connection
	// and retries. This saves one full tunnel round-trip (~200ms), critical for
	// latency-sensitive connections like YouTube CDN.
	replyStart := time.Now()
	if err := protocol.WriteSocks5Reply(conn, protocol.RepSuccess, net.IPv4zero, 0); err != nil {
		slog.Error("failed to write socks5 reply", "err", err, "target", target,
			"handshake", handshakeElapsed.Round(time.Millisecond),
			"request_read", requestElapsed.Round(time.Millisecond),
			"session_wait", sessionElapsed.Round(time.Millisecond),
			"stream_open", streamElapsed.Round(time.Millisecond),
			"target_write", targetWriteElapsed.Round(time.Millisecond),
			"reply_write", time.Since(replyStart).Round(time.Millisecond),
			"elapsed", time.Since(start).Round(time.Millisecond))
		return
	}
	replyElapsed := time.Since(replyStart)

	slog.Debug("socks5 pipeline ready", "target", target, "remote", remote,
		"handshake", handshakeElapsed.Round(time.Millisecond),
		"request_read", requestElapsed.Round(time.Millisecond),
		"session_wait", sessionElapsed.Round(time.Millisecond),
		"stream_open", streamElapsed.Round(time.Millisecond),
		"target_write", targetWriteElapsed.Round(time.Millisecond),
		"reply_write", replyElapsed.Round(time.Millisecond),
		"setup_total", time.Since(start).Round(time.Millisecond))

	// Step 7: Relay data bidirectionally
	stats := pkg.Relay(conn, stream, &relayBufPool)
	slog.Info("relay done", "target", target,
		"session_id", session.ID(),
		"duration", stats.Duration.Round(time.Millisecond),
		"upload", stats.AToB.Bytes,
		"download", stats.BToA.Bytes,
		"upload_result", stats.AToB.Result,
		"download_result", stats.BToA.Result,
		"upload_ttfb", stats.AToB.FirstByte.Round(time.Millisecond),
		"download_ttfb", stats.BToA.FirstByte.Round(time.Millisecond),
		"upload_started", stats.AToB.FirstByteSeen,
		"download_started", stats.BToA.FirstByteSeen,
	)
}
