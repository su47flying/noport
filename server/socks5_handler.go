package server

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

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

	// Step 1: SOCKS5 handshake (with timeout)
	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err := protocol.HandleSocks5Handshake(conn); err != nil {
		slog.Debug("socks5 handshake failed", "remote", remote, "err", err)
		return
	}

	// Step 2: Read CONNECT request
	req, err := protocol.ReadSocks5Request(conn)
	if err != nil {
		slog.Debug("socks5 request failed", "remote", remote, "err", err)
		protocol.WriteSocks5Reply(conn, protocol.RepCmdNotSupported, nil, 0)
		return
	}
	// Clear deadline after handshake/request phase
	conn.SetDeadline(time.Time{})

	target := req.Target()
	poolSize, totalStreams := s.dataQueue.Stats()
	slog.Debug("socks5 connect", "target", target, "remote", remote,
		"pool_size", poolSize, "active_streams", totalStreams)

	// Step 3: Get a MuxSession from data queue (with retry)
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for socks5", "err", err, "target", target, "remote", remote)
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}

	// Step 4: Open a mux stream
	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target,
			"pool_size", s.dataQueue.Size(), "session_streams", session.NumStreams())
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}
	defer stream.Close()

	// Step 5: Send target address through the stream (length-prefixed)
	if err := writeTargetToStream(stream, target); err != nil {
		slog.Error("failed to write target to stream", "err", err, "target", target)
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}

	// Step 6: Wait for client to confirm target connection (1-byte response).
	// 0x00 = success (client connected to target)
	// 0x01 = failure (client could not connect to target)
	var result [1]byte
	if _, err := io.ReadFull(stream, result[:]); err != nil {
		slog.Error("failed to read connect result from client", "err", err, "target", target)
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}
	if result[0] != 0x00 {
		slog.Warn("client reported connect failure", "target", target)
		protocol.WriteSocks5Reply(conn, protocol.RepHostUnreach, nil, 0)
		return
	}

	// Step 7: Send SOCKS5 success reply to APP (target is connected)
	if err := protocol.WriteSocks5Reply(conn, protocol.RepSuccess, net.IPv4zero, 0); err != nil {
		slog.Error("failed to write socks5 reply", "err", err, "target", target)
		return
	}

	// Step 8: Relay data bidirectionally
	stats := relay(conn, stream)
	slog.Info("relay done", "target", target,
		"duration", stats.duration.Round(time.Millisecond),
		"upload", stats.upload,
		"download", stats.download,
	)
}

// relayResult holds stats from a bidirectional relay.
type relayResult struct {
	upload   int64         // bytes: left → right
	download int64         // bytes: right → left
	duration time.Duration
}

// relay copies data bidirectionally between two connections (gost transport pattern).
// Two goroutines copy independently. When the first direction finishes,
// both connections are closed to unblock the other direction.
// Caller's deferred Close() calls are safe (idempotent).
func relay(left, right net.Conn) relayResult {
	start := time.Now()
	var upload, download int64
	var uploadErr, downloadErr error

	ch := make(chan struct{}, 2)

	// left → right (upload: SOCKS5 conn → mux stream)
	go func() {
		buf := relayBufPool.Get().([]byte)
		upload, uploadErr = io.CopyBuffer(right, left, buf)
		relayBufPool.Put(buf)
		ch <- struct{}{}
	}()

	// right → left (download: mux stream → SOCKS5 conn)
	go func() {
		buf := relayBufPool.Get().([]byte)
		download, downloadErr = io.CopyBuffer(left, right, buf)
		relayBufPool.Put(buf)
		ch <- struct{}{}
	}()

	// Wait for first direction to complete, then close both to unblock the other
	<-ch
	left.Close()
	right.Close()
	<-ch

	if uploadErr != nil && uploadErr != io.EOF {
		slog.Debug("relay upload error", "err", uploadErr, "bytes", upload)
	}
	if downloadErr != nil && downloadErr != io.EOF {
		slog.Debug("relay download error", "err", downloadErr, "bytes", download)
	}

	return relayResult{
		upload:   upload,
		download: download,
		duration: time.Since(start),
	}
}
