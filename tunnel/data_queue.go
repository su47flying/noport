package tunnel

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"noport/crypto"
)

var ErrPoolClosed = errors.New("data queue pool is closed")
var ErrNoConnections = errors.New("no connections available")

// DataQueue manages a pool of mux sessions over encrypted TCP connections.
// Each TCP connection in the pool carries a MuxSession for multiplexing.
type DataQueue struct {
	mu       sync.RWMutex
	sessions []*MuxSession
	cipher   crypto.Cipher
	closed   bool
	isServer bool

	// Round-robin index for load balancing across sessions
	rrIndex uint64
}

// NewDataQueue creates a new data queue pool.
// cipher can be nil for no encryption.
func NewDataQueue(cipher crypto.Cipher, isServer bool) *DataQueue {
	return &DataQueue{
		cipher:   cipher,
		isServer: isServer,
	}
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

// GetSession returns an active MuxSession from the pool using round-robin selection.
// Skips and removes closed sessions. Returns error if pool is empty or closed.
func (dq *DataQueue) GetSession() (*MuxSession, error) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.closed {
		return nil, ErrPoolClosed
	}

	// Remove dead sessions first
	alive := dq.sessions[:0]
	for _, s := range dq.sessions {
		if !s.IsClosed() {
			alive = append(alive, s)
		} else {
			slog.Debug("data queue: pruned dead session")
		}
	}
	dq.sessions = alive

	if len(dq.sessions) == 0 {
		return nil, ErrNoConnections
	}

	idx := atomic.AddUint64(&dq.rrIndex, 1) - 1
	return dq.sessions[idx%uint64(len(dq.sessions))], nil
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

// Close closes all sessions and the pool.
func (dq *DataQueue) Close() error {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.closed {
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

	slog.Debug("data queue: pool closed")
	return firstErr
}

// Sessions returns a snapshot of current sessions (for iteration).
func (dq *DataQueue) Sessions() []*MuxSession {
	dq.mu.RLock()
	defer dq.mu.RUnlock()

	snapshot := make([]*MuxSession, len(dq.sessions))
	copy(snapshot, dq.sessions)
	return snapshot
}
