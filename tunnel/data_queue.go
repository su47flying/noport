package tunnel

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"noport/crypto"
)

var ErrPoolClosed = errors.New("data queue pool is closed")
var ErrNoConnections = errors.New("no connections available")

// DataQueue manages a pool of mux sessions over encrypted TCP connections.
// Each TCP connection in the pool carries a MuxSession for multiplexing.
type DataQueue struct {
	mu        sync.RWMutex
	sessions  []*MuxSession
	cipher    crypto.Cipher
	closed    bool
	isServer  bool
	pruneDone chan struct{}
}

// NewDataQueue creates a new data queue pool.
// cipher can be nil for no encryption.
func NewDataQueue(cipher crypto.Cipher, isServer bool) *DataQueue {
	dq := &DataQueue{
		cipher:    cipher,
		isServer:  isServer,
		pruneDone: make(chan struct{}),
	}
	dq.StartPrune()
	return dq
}

// AddConn adds a new TCP connection to the pool.
// The connection is wrapped with encryption (if cipher is set),
// then a MuxSession is created over it.
func (dq *DataQueue) AddConn(conn net.Conn) (*MuxSession, error) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.closed {
		conn.Close()
		return nil, ErrPoolClosed
	}

	wrapped := conn
	if dq.cipher != nil {
		wrapped = dq.cipher.WrapConn(conn)
	}

	session := NewMuxSession(wrapped, dq.isServer)
	dq.sessions = append(dq.sessions, session)

	slog.Debug("data queue: added connection", "pool_size", len(dq.sessions))
	return session, nil
}

// GetSession returns an active MuxSession from the pool using a
// bandwidth-aware least-loaded selection: the session with the smallest
// write backlog (queued + in-flight bytes) wins, with stream count as
// the tiebreaker. This prevents a heavy stream (e.g. video) from dragging
// unrelated streams placed on the same TCP — new streams naturally land
// on idle sessions instead of stacking on the busiest one.
// Skips closed sessions. Returns error if pool is empty or closed.
func (dq *DataQueue) GetSession() (*MuxSession, error) {
	dq.mu.RLock()
	defer dq.mu.RUnlock()

	if dq.closed {
		return nil, ErrPoolClosed
	}

	var best *MuxSession
	var bestInflight int64
	var bestStreams int
	aliveCount := 0

	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		aliveCount++
		inflight := s.InflightBytes()
		streams := s.NumStreams()
		if best == nil ||
			inflight < bestInflight ||
			(inflight == bestInflight && streams < bestStreams) {
			best = s
			bestInflight = inflight
			bestStreams = streams
		}
	}

	if best == nil {
		return nil, ErrNoConnections
	}

	slog.Debug("data queue: selected session",
		"session_id", best.ID(),
		"inflight_bytes", bestInflight,
		"streams", bestStreams,
		"pool_size", aliveCount,
	)
	return best, nil
}

// RemoveSession removes a session from the pool (e.g., when its underlying conn dies).
func (dq *DataQueue) RemoveSession(session *MuxSession) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	for i, s := range dq.sessions {
		if s == session {
			dq.sessions = append(dq.sessions[:i], dq.sessions[i+1:]...)
			slog.Debug("data queue: removed session", "pool_size", len(dq.sessions))
			return
		}
	}
}

// Size returns the number of active sessions in the pool.
func (dq *DataQueue) Size() int {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	return len(dq.sessions)
}

// Stats returns pool_size and total active streams across all sessions.
func (dq *DataQueue) Stats() (poolSize int, totalStreams int) {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	poolSize = len(dq.sessions)
	for _, s := range dq.sessions {
		totalStreams += s.NumStreams()
	}
	return
}

// StartPrune starts a background goroutine that periodically removes dead sessions.
func (dq *DataQueue) StartPrune() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				dq.mu.Lock()
				if dq.closed {
					dq.mu.Unlock()
					return
				}
				alive := dq.sessions[:0]
				for _, s := range dq.sessions {
					if !s.IsClosed() {
						alive = append(alive, s)
					} else {
						slog.Debug("data queue: pruned dead session")
					}
				}
				dq.sessions = alive
				dq.mu.Unlock()
			case <-dq.pruneDone:
				return
			}
		}
	}()
}

// Close closes all sessions and the pool.
func (dq *DataQueue) Close() error {
	dq.mu.Lock()

	if dq.closed {
		dq.mu.Unlock()
		return nil
	}
	dq.closed = true

	var firstErr error
	for _, s := range dq.sessions {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	dq.sessions = nil
	dq.mu.Unlock()

	close(dq.pruneDone)

	slog.Debug("data queue: pool closed")
	return firstErr
}

// SessionInfo holds per-session stats for observability logging.
type SessionInfo struct {
	ID       uint64
	Streams  int
	Inflight int64
	Closed   bool
}

// DetailedStats returns per-session info for periodic logging.
func (dq *DataQueue) DetailedStats() []SessionInfo {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	infos := make([]SessionInfo, len(dq.sessions))
	for i, s := range dq.sessions {
		infos[i] = SessionInfo{
			ID:       s.ID(),
			Streams:  s.NumStreams(),
			Inflight: s.InflightBytes(),
			Closed:   s.IsClosed(),
		}
	}
	return infos
}

// Sessions returns a snapshot of current sessions (for iteration).
func (dq *DataQueue) Sessions() []*MuxSession {
	dq.mu.RLock()
	defer dq.mu.RUnlock()

	snapshot := make([]*MuxSession, len(dq.sessions))
	copy(snapshot, dq.sessions)
	return snapshot
}
