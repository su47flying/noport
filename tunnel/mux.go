package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MuxHeaderLen = 9

	FlagData  byte = 0x00
	FlagOpen  byte = 0x01
	FlagClose byte = 0x02
	FlagReset byte = 0x03

	maxMuxPayload = 32768 // 32KB max payload per frame
)

// MuxSession manages multiplexed streams over a single net.Conn.
type MuxSession struct {
	conn    net.Conn
	streams map[uint32]*MuxStream
	mu      sync.RWMutex
	nextID  uint32
	closed  atomic.Bool
	accept  chan *MuxStream
	writeMu sync.Mutex
	// isServer determines ID parity: even IDs for server, odd for client.
	isServer bool
	done     chan struct{}
}

// NewMuxSession creates a new mux session over the given conn.
// isServer determines stream ID allocation (even for server, odd for client).
func NewMuxSession(conn net.Conn, isServer bool) *MuxSession {
	s := &MuxSession{
		conn:     conn,
		streams:  make(map[uint32]*MuxStream),
		accept:   make(chan *MuxStream, 64),
		isServer: isServer,
		done:     make(chan struct{}),
	}
	if isServer {
		s.nextID = 2
	} else {
		s.nextID = 1
	}
	go s.serve()
	return s
}

// Accept waits for and returns the next incoming stream opened by the remote side.
func (s *MuxSession) Accept() (*MuxStream, error) {
	select {
	case st, ok := <-s.accept:
		if !ok {
			return nil, fmt.Errorf("mux session closed")
		}
		return st, nil
	case <-s.done:
		return nil, fmt.Errorf("mux session closed")
	}
}

// Open creates a new outgoing stream.
func (s *MuxSession) Open() (*MuxStream, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("mux session closed")
	}

	s.mu.Lock()
	id := s.nextID
	s.nextID += 2
	st := newMuxStream(id, s)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(id, FlagOpen, nil); err != nil {
		s.mu.Lock()
		delete(s.streams, id)
		s.mu.Unlock()
		return nil, err
	}
	return st, nil
}

// Close closes the mux session and all streams.
func (s *MuxSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.done)

	s.mu.Lock()
	for _, st := range s.streams {
		st.closeLocal()
	}
	s.streams = make(map[uint32]*MuxStream)
	s.mu.Unlock()

	close(s.accept)
	return s.conn.Close()
}

// NumStreams returns the number of active streams.
func (s *MuxSession) NumStreams() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams)
}

// serve reads frames from the underlying conn and dispatches to streams.
func (s *MuxSession) serve() {
	defer s.Close()

	header := make([]byte, MuxHeaderLen)
	for {
		if _, err := io.ReadFull(s.conn, header); err != nil {
			if !s.closed.Load() {
				slog.Debug("mux serve: read header error", "err", err)
			}
			return
		}

		streamID := binary.BigEndian.Uint32(header[0:4])
		flag := header[4]
		length := binary.BigEndian.Uint32(header[5:9])

		if length > maxMuxPayload {
			slog.Error("mux serve: payload too large", "length", length)
			return
		}

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				if !s.closed.Load() {
					slog.Debug("mux serve: read payload error", "err", err)
				}
				return
			}
		}

		switch flag {
		case FlagOpen:
			s.mu.Lock()
			if _, exists := s.streams[streamID]; exists {
				s.mu.Unlock()
				slog.Warn("mux serve: duplicate stream open", "streamID", streamID)
				continue
			}
			st := newMuxStream(streamID, s)
			s.streams[streamID] = st
			s.mu.Unlock()

			select {
			case s.accept <- st:
			case <-s.done:
				return
			}

		case FlagData:
			s.mu.RLock()
			st, ok := s.streams[streamID]
			s.mu.RUnlock()
			if !ok {
				slog.Debug("mux serve: data for unknown stream", "streamID", streamID)
				continue
			}
			if len(payload) > 0 {
				select {
				case st.readBuf <- payload:
				case <-st.closeCh:
				case <-s.done:
					return
				}
			}

		case FlagClose, FlagReset:
			s.mu.Lock()
			st, ok := s.streams[streamID]
			if ok {
				delete(s.streams, streamID)
			}
			s.mu.Unlock()
			if ok {
				st.closeLocal()
			}
		}
	}
}

// writeFrame writes a single mux frame to the underlying conn (thread-safe).
func (s *MuxSession) writeFrame(streamID uint32, flag byte, data []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("mux session closed")
	}

	header := make([]byte, MuxHeaderLen)
	binary.BigEndian.PutUint32(header[0:4], streamID)
	header[4] = flag
	binary.BigEndian.PutUint32(header[5:9], uint32(len(data)))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.conn.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := s.conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func (s *MuxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// MuxStream represents a single multiplexed stream within a MuxSession.
// It implements the net.Conn interface.
type MuxStream struct {
	id       uint32
	session  *MuxSession
	readBuf  chan []byte
	readLeft []byte
	closed   atomic.Bool
	closeCh  chan struct{}
}

func newMuxStream(id uint32, session *MuxSession) *MuxStream {
	return &MuxStream{
		id:      id,
		session: session,
		readBuf: make(chan []byte, 256),
		closeCh: make(chan struct{}),
	}
}

// Read reads data from the stream.
func (st *MuxStream) Read(p []byte) (int, error) {
	if len(st.readLeft) > 0 {
		n := copy(p, st.readLeft)
		st.readLeft = st.readLeft[n:]
		return n, nil
	}

	select {
	case data, ok := <-st.readBuf:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			st.readLeft = data[n:]
		}
		return n, nil
	case <-st.closeCh:
		// Drain remaining buffered data before returning EOF.
		select {
		case data, ok := <-st.readBuf:
			if !ok {
				return 0, io.EOF
			}
			n := copy(p, data)
			if n < len(data) {
				st.readLeft = data[n:]
			}
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

// Write writes data to the stream, splitting into frames if necessary.
func (st *MuxStream) Write(p []byte) (int, error) {
	if st.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxMuxPayload {
			chunk = chunk[:maxMuxPayload]
		}
		if err := st.session.writeFrame(st.id, FlagData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close closes the stream.
func (st *MuxStream) Close() error {
	if st.closed.Swap(true) {
		return nil
	}
	st.session.removeStream(st.id)
	err := st.session.writeFrame(st.id, FlagClose, nil)
	close(st.closeCh)
	return err
}

// closeLocal closes the stream locally without sending a frame.
func (st *MuxStream) closeLocal() {
	if st.closed.Swap(true) {
		return
	}
	close(st.closeCh)
}

func (st *MuxStream) LocalAddr() net.Addr {
	return st.session.conn.LocalAddr()
}

func (st *MuxStream) RemoteAddr() net.Addr {
	return st.session.conn.RemoteAddr()
}

func (st *MuxStream) SetDeadline(t time.Time) error {
	return nil
}

func (st *MuxStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (st *MuxStream) SetWriteDeadline(t time.Time) error {
	return nil
}

// Compile-time check that MuxStream satisfies net.Conn.
var _ net.Conn = (*MuxStream)(nil)
