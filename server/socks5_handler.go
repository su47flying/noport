package server

import (
	"io"
	"log/slog"
	"net"
	"time"

	"noport/protocol"
)

const (
	socks5HandshakeTimeout = 10 * time.Second
	socks5StreamTimeout    = 15 * time.Second
)

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
	slog.Debug("socks5 connect", "target", target, "remote", remote)

	// Step 3: Get a MuxSession from data queue (with retry)
	session, err := s.getSessionWithRetry()
	if err != nil {
		slog.Error("no session for socks5", "err", err, "target", target)
		protocol.WriteSocks5Reply(conn, protocol.RepGeneralFailure, nil, 0)
		return
	}

	// Step 4: Open a mux stream
	stream, err := session.Open()
	if err != nil {
		slog.Error("failed to open stream", "err", err, "target", target)
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

	// Step 6: Read 1-byte response from client (0x00 = success), with timeout
	stream.SetDeadline(time.Now().Add(socks5StreamTimeout))
	var resp [1]byte
	if _, err := io.ReadFull(stream, resp[:]); err != nil {
		slog.Error("failed to read stream response", "err", err, "target", target)
		protocol.WriteSocks5Reply(conn, protocol.RepHostUnreach, nil, 0)
		return
	}
	stream.SetDeadline(time.Time{})

	if resp[0] != 0x00 {
		slog.Debug("client reported failure for target", "target", target, "code", resp[0])
		protocol.WriteSocks5Reply(conn, protocol.RepHostUnreach, nil, 0)
		return
	}

	// Step 7: Send SOCKS5 success reply
	if err := protocol.WriteSocks5Reply(conn, protocol.RepSuccess, net.IPv4zero, 0); err != nil {
		slog.Error("failed to write socks5 reply", "err", err, "target", target)
		return
	}

	// Step 8: Relay data bidirectionally
	relay(conn, stream)
}

// relay copies data bidirectionally between two connections.
// When one direction finishes, the other is terminated promptly.
func relay(left, right net.Conn) {
	done := make(chan struct{})

	go func() {
		io.Copy(right, left)
		// Signal the other direction to stop
		if tc, ok := right.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			right.SetReadDeadline(time.Now())
		}
		close(done)
	}()

	io.Copy(left, right)
	if tc, ok := left.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		left.SetReadDeadline(time.Now())
	}

	<-done
}
