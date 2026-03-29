package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
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

	maxMuxPayload = 65536 // 64KB max payload per frame
)

// Buffer pools to reduce GC pressure on hot paths
var (
	frameBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, MuxHeaderLen+maxMuxPayload)
			return &b
		},
	}
	payloadBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, maxMuxPayload)
			return &b
		},
	}
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
		accept:   make(chan *MuxStream, 256),
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

// IsClosed returns whether the session has been closed.
func (s *MuxSession) IsClosed() bool {
	return s.closed.Load()
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

		// Use pooled buffer for payload to reduce allocations
		var payload []byte
		var payloadBufp *[]byte
		if length > 0 {
			payloadBufp = payloadBufPool.Get().(*[]byte)
			payload = (*payloadBufp)[:length]
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				payloadBufPool.Put(payloadBufp)
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
				st.pushData(payload)
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

		// Return pooled payload buffer (pushData copies into bytes.Buffer)
		if payloadBufp != nil {
			payloadBufPool.Put(payloadBufp)
		}
	}
}

// writeFrame writes a single mux frame to the underlying conn (thread-safe).
// Header and payload are combined into a single write to avoid interleaving.
func (s *MuxSession) writeFrame(streamID uint32, flag byte, data []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("mux session closed")
	}

	frameLen := MuxHeaderLen + len(data)

	// Use pooled buffer to reduce allocations on hot path
	bufp := frameBufPool.Get().(*[]byte)
	buf := (*bufp)[:frameLen]

	binary.BigEndian.PutUint32(buf[0:4], streamID)
	buf[4] = flag
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(data)))
	if len(data) > 0 {
		copy(buf[MuxHeaderLen:], data)
	}

	s.writeMu.Lock()
	_, err := s.conn.Write(buf)
	s.writeMu.Unlock()

	frameBufPool.Put(bufp)
	return err
}

func (s *MuxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// MuxStream represents a single multiplexed stream within a MuxSession.
// It implements the net.Conn interface.
// Uses bytes.Buffer + sync.Cond instead of channel to avoid head-of-line blocking.
type MuxStream struct {
	id      uint32
	session *MuxSession

	mu           sync.Mutex
	cond         *sync.Cond
	buf          bytes.Buffer // incoming data buffer
	closed       atomic.Bool
	closeCh      chan struct{}
	readDeadline time.Time // guarded by mu
}

func newMuxStream(id uint32, session *MuxSession) *MuxStream {
	st := &MuxStream{
		id:      id,
		session: session,
		closeCh: make(chan struct{}),
	}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// pushData appends data to the stream's buffer (called by serve(), never blocks).
func (st *MuxStream) pushData(data []byte) {
	st.mu.Lock()
	st.buf.Write(data)
	st.mu.Unlock()
	st.cond.Signal()
}

// Read reads data from the stream's buffer.
// Blocks until data is available, the stream is closed, or the read deadline expires.
func (st *MuxStream) Read(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	for st.buf.Len() == 0 {
		if st.closed.Load() {
			return 0, io.EOF
		}

		dl := st.readDeadline
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			// Timer wakes us up when the deadline expires
			timer := time.AfterFunc(d, func() {
				st.cond.Broadcast()
			})
			st.cond.Wait()
			timer.Stop()
		} else {
			st.cond.Wait()
		}
	}
	return st.buf.Read(p)
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
	st.cond.Broadcast() // wake up any blocked readers
	return err
}

// closeLocal closes the stream locally without sending a frame.
func (st *MuxStream) closeLocal() {
	if st.closed.Swap(true) {
		return
	}
	close(st.closeCh)
	st.cond.Broadcast() // wake up any blocked readers
}

func (st *MuxStream) LocalAddr() net.Addr {
	return st.session.conn.LocalAddr()
}

func (st *MuxStream) RemoteAddr() net.Addr {
	return st.session.conn.RemoteAddr()
}

func (st *MuxStream) SetDeadline(t time.Time) error {
	return st.SetReadDeadline(t)
}

func (st *MuxStream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline = t
	st.mu.Unlock()
	st.cond.Broadcast() // wake up any blocked readers to check deadline
	return nil
}

func (st *MuxStream) SetWriteDeadline(t time.Time) error {
	return nil
}

// Compile-time check that MuxStream satisfies net.Conn.
var _ net.Conn = (*MuxStream)(nil)
