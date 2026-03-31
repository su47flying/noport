package tunnel

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtaci/smux"
)

// smux configuration optimized for proxy tunneling
var smuxConfig = &smux.Config{
	Version:           2,
	KeepAliveInterval: 10 * time.Second,
	KeepAliveTimeout:  30 * time.Second,
	MaxFrameSize:      65535,           // 64KB
	MaxReceiveBuffer:  4 * 1024 * 1024, // 4MB total receive buffer
	MaxStreamBuffer:   2 * 1024 * 1024, // 2MB per stream buffer
}

// MuxSession manages multiplexed streams over a single net.Conn using smux.
type MuxSession struct {
	session *smux.Session
	conn    net.Conn
	closed  atomic.Bool
}

// NewMuxSession creates a new mux session over the given conn.
// isServer: true for the TCP-accepting side, false for the TCP-dialing side.
func NewMuxSession(conn net.Conn, isServer bool) (*MuxSession, error) {
	var session *smux.Session
	var err error
	if isServer {
		session, err = smux.Server(conn, smuxConfig)
	} else {
		session, err = smux.Client(conn, smuxConfig)
	}
	if err != nil {
		slog.Error("failed to create smux session", "err", err, "isServer", isServer)
		conn.Close()
		return nil, err
	}
	return &MuxSession{session: session, conn: conn}, nil
}

// Open creates a new outgoing stream.
func (s *MuxSession) Open() (*MuxStream, error) {
	stream, err := s.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &MuxStream{stream: stream, session: s}, nil
}

// Accept waits for and returns the next incoming stream.
func (s *MuxSession) Accept() (*MuxStream, error) {
	stream, err := s.session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &MuxStream{stream: stream, session: s}, nil
}

// Close closes the session and underlying connection.
func (s *MuxSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.session.Close()
}

// IsClosed returns whether the session has been closed.
func (s *MuxSession) IsClosed() bool {
	return s.session.IsClosed()
}

// NumStreams returns the number of active streams.
func (s *MuxSession) NumStreams() int {
	return s.session.NumStreams()
}

// MuxStream wraps a smux.Stream, implementing net.Conn.
type MuxStream struct {
	stream  *smux.Stream
	session *MuxSession
}

func (st *MuxStream) Read(p []byte) (int, error) {
	return st.stream.Read(p)
}

func (st *MuxStream) Write(p []byte) (int, error) {
	return st.stream.Write(p)
}

func (st *MuxStream) Close() error {
	return st.stream.Close()
}

func (st *MuxStream) LocalAddr() net.Addr {
	return st.session.conn.LocalAddr()
}

func (st *MuxStream) RemoteAddr() net.Addr {
	return st.session.conn.RemoteAddr()
}

func (st *MuxStream) SetDeadline(t time.Time) error {
	return st.stream.SetDeadline(t)
}

func (st *MuxStream) SetReadDeadline(t time.Time) error {
	return st.stream.SetReadDeadline(t)
}

func (st *MuxStream) SetWriteDeadline(t time.Time) error {
	return st.stream.SetWriteDeadline(t)
}

// Compile-time check that MuxStream satisfies net.Conn.
var _ net.Conn = (*MuxStream)(nil)
