package tunnel

import (
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

	// maxMuxPayload is the maximum payload size accepted on the wire (per
	// frame). Kept at 64KB for backward compatibility with peers that still
	// emit larger frames.
	maxMuxPayload = 65536

	// writeChunkSize is the maximum payload size we *emit* in a single frame.
	// A smaller value reduces head-of-line blocking on a shared session: when
	// one stream pushes a large buffer, other streams' frames only have to
	// wait for at most one ~16KB write to complete instead of a full 64KB.
	// The 0.5% header overhead is negligible.
	writeChunkSize = 16 * 1024

	// writeDeadline bounds the time a single frame may spend in conn.Write.
	// This is a *catastrophic-stall* safety net, NOT a congestion detector.
	// A multiplexed TCP carrying video over a constrained upstream may
	// legitimately block for tens of seconds while the kernel send buffer
	// drains; killing the session in that window would tear down every
	// unrelated stream sharing it (the regression observed in v0.0.7).
	// Idle / dead-peer detection is handled by TCP keepalive (pkg.TuneTCP).
	writeDeadline = 10 * time.Minute
)

// sessionIDCounter assigns a unique ID to each MuxSession for logging.
var sessionIDCounter uint64

// Buffer pools to reduce GC pressure on hot paths.
// Frame buffers must accommodate the maximum *received* frame, since the same
// pool is used both when assembling outgoing frames (header + writeChunkSize)
// and reading peer frames (header + maxMuxPayload).
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

// chunk holds a reference to a pooled buffer passed from serve() to a stream.
type chunk struct {
	data []byte  // payload slice (sub-slice of pooled buffer)
	bufp *[]byte // pool pointer; returned when chunk is fully consumed
	off  int     // read cursor within data
}

// pendingFrame is a frame queued for the writeLoop to send.
type pendingFrame struct {
	buf   []byte     // fully serialized frame (header + payload)
	bufp  *[]byte    // pool pointer to return after write
	errCh chan<- error // nil for fire-and-forget
}

// MuxSession manages multiplexed streams over a single net.Conn.
type MuxSession struct {
	id      uint64 // unique session ID for logging
	conn    net.Conn
	streams map[uint32]*MuxStream
	mu      sync.RWMutex
	nextID  uint32
	closed  atomic.Bool
	accept  chan *MuxStream
	writeCh chan pendingFrame
	// inflightBytes is the total number of payload+header bytes currently
	// queued in writeCh or being written to conn. The DataQueue uses it to
	// pick the least-loaded session by *bandwidth backlog* rather than by
	// stream count, which prevents a high-bandwidth stream (e.g. video) from
	// dragging unrelated streams sharing the same TCP.
	inflightBytes atomic.Int64
	// isServer determines ID parity: even IDs for server, odd for client.
	isServer bool
	done     chan struct{}
}

// NewMuxSession creates a new mux session over the given conn.
// isServer determines stream ID allocation (even for server, odd for client).
func NewMuxSession(conn net.Conn, isServer bool) *MuxSession {
	s := &MuxSession{
		id:       atomic.AddUint64(&sessionIDCounter, 1),
		conn:     conn,
		streams:  make(map[uint32]*MuxStream),
		accept:   make(chan *MuxStream, 256),
		writeCh:  make(chan pendingFrame, 256),
		isServer: isServer,
		done:     make(chan struct{}),
	}
	if isServer {
		s.nextID = 2
	} else {
		s.nextID = 1
	}
	go s.serve()
	go s.writeLoop()
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

// InflightBytes returns the current write backlog (queued + being written) in
// bytes. Used by DataQueue for bandwidth-aware session selection.
func (s *MuxSession) InflightBytes() int64 {
	return s.inflightBytes.Load()
}

// Close closes the mux session and all streams.
func (s *MuxSession) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	// Signal writeLoop and any blocked writeFrame callers to bail out.
	// We deliberately do NOT close(writeCh): a producer racing with the
	// close would panic with "send on closed channel". Producers gate on
	// s.done instead.
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

// ID returns the unique session identifier.
func (s *MuxSession) ID() uint64 {
	return s.id
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
				// Stream already removed (we issued FlagReset, or peer
				// recycled an id). Silently drop — this is benign racing
				// with normal teardown and used to flood logs.
				slog.Debug("mux serve: data for unknown stream", "streamID", streamID)
				continue
			}
			if len(payload) > 0 {
				// pushData internally drops the chunk (and returns the
				// pooled buffer) if the stream has been locally closed,
				// so a half-closed peer can't grow our memory.
				st.pushData(payload, payloadBufp)
				payloadBufp = nil // ownership transferred (or dropped by pushData)
			}

		case FlagClose, FlagReset:
			s.mu.Lock()
			st, ok := s.streams[streamID]
			if ok {
				delete(s.streams, streamID)
			}
			s.mu.Unlock()
			if ok {
				// If the peer initiated the close (we hadn't closed
				// locally yet), echo FlagClose back so the peer can
				// release its half of the map. With both Close() and
				// this echo path, both ends always converge on an
				// empty map entry without the race that produces
				// "data for unknown stream" noise.
				peerInitiated := !st.closed.Load() && flag == FlagClose
				st.closeLocal()
				if peerInitiated {
					go func(id uint32) {
						_ = s.writeFrame(id, FlagClose, nil)
					}(streamID)
				}
			}
		}

		// Return pooled payload buffer only if ownership was not transferred
		if payloadBufp != nil {
			payloadBufPool.Put(payloadBufp)
		}
	}
}

// writeLoop is the single goroutine that writes frames to the underlying conn.
// It exits either when s.done is closed or when conn.Write fails (including
// the per-frame deadline expiring), at which point it tears down the session.
func (s *MuxSession) writeLoop() {
	// Best-effort detection of an underlying TCP conn for deadline support.
	// All current ciphers (chacha20, xor) wrap via crypto.encryptedConn which
	// embeds net.Conn, so SetWriteDeadline transparently forwards to TCP.
	type deadliner interface {
		SetWriteDeadline(t time.Time) error
	}
	dl, _ := s.conn.(deadliner)

	for {
		select {
		case <-s.done:
			return
		case pf := <-s.writeCh:
			if dl != nil {
				_ = dl.SetWriteDeadline(time.Now().Add(writeDeadline))
			}
			start := time.Now()
			_, err := s.conn.Write(pf.buf)
			if dl != nil {
				_ = dl.SetWriteDeadline(time.Time{})
			}

			frameLen := int64(len(pf.buf))
			s.inflightBytes.Add(-frameLen)

			if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
				slog.Warn("mux slow write",
					"session_id", s.id,
					"elapsed", elapsed,
					"frame_size", len(pf.buf),
					"inflight_bytes", s.inflightBytes.Load(),
					"queue_depth", len(s.writeCh),
				)
			}

			frameBufPool.Put(pf.bufp)
			if pf.errCh != nil {
				// Non-blocking send: if the producer already gave up via
				// s.done, the channel is buffered (cap 1) and never read,
				// so a plain send still succeeds — but we keep the select
				// for symmetry and future-proofing.
				select {
				case pf.errCh <- err:
				default:
				}
			}
			if err != nil {
				slog.Warn("mux write error, tearing down session",
					"session_id", s.id,
					"err", err,
				)
				go s.Close()
				return
			}
		}
	}
}

// writeFrame queues a single mux frame for writing via the writeLoop (thread-safe).
// Header and payload are combined into a single buffer to avoid interleaving.
// Blocks until the frame has been fully written to the underlying conn (or the
// session is torn down). The synchronous ack guarantees per-stream write order
// and lets callers observe write errors immediately.
func (s *MuxSession) writeFrame(streamID uint32, flag byte, data []byte) error {
	if s.closed.Load() {
		return fmt.Errorf("mux session closed")
	}

	frameLen := MuxHeaderLen + len(data)

	bufp := frameBufPool.Get().(*[]byte)
	buf := (*bufp)[:frameLen]

	binary.BigEndian.PutUint32(buf[0:4], streamID)
	buf[4] = flag
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(data)))
	if len(data) > 0 {
		copy(buf[MuxHeaderLen:], data)
	}

	errCh := make(chan error, 1)
	pf := pendingFrame{buf: buf, bufp: bufp, errCh: errCh}

	// Account for backlog *before* enqueuing so GetSession sees pressure
	// even while the frame still sits in writeCh. writeLoop subtracts after
	// the actual TCP write completes.
	s.inflightBytes.Add(int64(frameLen))

	select {
	case s.writeCh <- pf:
		if qlen := len(s.writeCh); qlen > 64 {
			slog.Warn("mux write queue backlog",
				"session_id", s.id,
				"queue_depth", qlen,
				"stream_id", streamID,
				"inflight_bytes", s.inflightBytes.Load(),
			)
		}
	case <-s.done:
		s.inflightBytes.Add(-int64(frameLen))
		frameBufPool.Put(bufp)
		return fmt.Errorf("mux session closed")
	}

	select {
	case err := <-errCh:
		return err
	case <-s.done:
		// writeLoop may already have processed the frame and decremented
		// inflightBytes; if not, it will when it drains. Either way the
		// caller sees an error and the session is being torn down.
		return fmt.Errorf("mux session closed")
	}
}

func (s *MuxSession) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// MuxStream represents a single multiplexed stream within a MuxSession.
// It implements the net.Conn interface.
// Uses a linked list of pooled chunks + sync.Cond to avoid extra copies and
// head-of-line blocking.
type MuxStream struct {
	id      uint32
	session *MuxSession

	mu           sync.Mutex
	cond         *sync.Cond
	chunks       []chunk // incoming data chunks (zero-copy from serve)
	bufLen       int     // total unread bytes across all chunks
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

// pushData transfers ownership of a pooled buffer to the stream (called by
// serve(), never blocks). The caller must NOT return bufp to the pool.
//
// If the stream has been closed locally, the chunk is dropped and the buffer
// is returned to the pool immediately. This prevents a half-closed peer (one
// that hasn't yet seen our FlagClose) from growing our memory by continuing
// to send data on a stream whose reader is gone.
func (st *MuxStream) pushData(data []byte, bufp *[]byte) {
	st.mu.Lock()
	if st.closed.Load() {
		st.mu.Unlock()
		if bufp != nil {
			payloadBufPool.Put(bufp)
		}
		return
	}
	st.chunks = append(st.chunks, chunk{data: data, bufp: bufp, off: 0})
	st.bufLen += len(data)
	st.mu.Unlock()
	st.cond.Signal()
}

// Read reads data from the stream's buffer.
// Blocks until data is available, the stream is closed, or the read deadline expires.
func (st *MuxStream) Read(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()

	for st.bufLen == 0 {
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
	n := 0
	for n < len(p) && len(st.chunks) > 0 {
		c := &st.chunks[0]
		copied := copy(p[n:], c.data[c.off:])
		n += copied
		c.off += copied
		if c.off >= len(c.data) {
			if c.bufp != nil {
				payloadBufPool.Put(c.bufp)
			}
			st.chunks = st.chunks[1:]
		}
	}
	st.bufLen -= n
	return n, nil
}

// Write writes data to the stream, splitting into frames if necessary.
// Frames are bounded by writeChunkSize (not maxMuxPayload) to keep
// head-of-line blocking on a shared session within bounded latency: when
// many streams share one MuxSession, a stream pushing megabytes still
// yields the writeLoop every ~16KB so other streams' frames interleave.
func (st *MuxStream) Write(p []byte) (int, error) {
	if st.closed.Load() {
		return 0, fmt.Errorf("stream closed")
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > writeChunkSize {
			chunk = chunk[:writeChunkSize]
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
//
// We send FlagClose to the peer but deliberately do NOT remove the stream
// from the session's map immediately. The peer may still have in-flight data
// frames on the wire (sent before they processed our FlagClose); if we removed
// the stream now, those frames would log "data for unknown stream" and fight
// for serve()'s attention. Instead, the stream lingers in a closed-locally
// state — pushData drops incoming data and the entry is removed when the peer
// echoes FlagClose (or when the entire session tears down).
func (st *MuxStream) Close() error {
	if st.closed.Swap(true) {
		return nil
	}
	close(st.closeCh)
	st.cond.Broadcast() // wake up any blocked readers
	// Send FlagClose last so writeFrame's synchronous wait doesn't hold the
	// caller while readers are still spinning. Errors here are best-effort
	// — the session is being torn down or the peer has already gone.
	return st.session.writeFrame(st.id, FlagClose, nil)
}

// closeLocal closes the stream locally without sending a frame.
func (st *MuxStream) closeLocal() {
	if st.closed.Swap(true) {
		return
	}
	close(st.closeCh)
	st.cond.Broadcast()
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
