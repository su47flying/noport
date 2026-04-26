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
	mu       sync.RWMutex
	sessions []*MuxSession
	// connBySession records the underlying data TCP connection for each
	// mux session. The server checks out a whole session/connection pair
	// per proxied request and retires that pair when the request finishes.
	connBySession map[uint64]net.Conn
	leased        map[uint64]bool
	cipher        crypto.Cipher
	closed        bool
	isServer      bool
	pruneDone     chan struct{}
}

// NewDataQueue creates a new data queue pool.
// cipher can be nil for no encryption.
func NewDataQueue(cipher crypto.Cipher, isServer bool) *DataQueue {
	dq := &DataQueue{
		cipher:        cipher,
		isServer:      isServer,
		connBySession: make(map[uint64]net.Conn),
		leased:        make(map[uint64]bool),
		pruneDone:     make(chan struct{}),
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
	dq.connBySession[session.ID()] = conn

	slog.Debug("data queue: added connection",
		"session_id", session.ID(),
		"remote", conn.RemoteAddr(),
		"pool_size", len(dq.sessions),
	)
	return session, nil
}

// GetSession checks out one idle MuxSession exclusively for one proxied
// request. A checked-out session is never returned to the idle pool; the
// caller must retire it with CloseSession when the request finishes.
// This deliberately avoids muxing unrelated user requests over the same
// data TCP connection, eliminating cross-request head-of-line blocking.
func (dq *DataQueue) GetSession() (*MuxSession, error) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.closed {
		return nil, ErrPoolClosed
	}

	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		if dq.leased[s.ID()] || s.NumStreams() != 0 {
			continue
		}

		dq.leased[s.ID()] = true
		conn := dq.connBySession[s.ID()]
		slog.Debug("data queue: checked out dedicated session",
			"session_id", s.ID(),
			"remote", remoteAddr(conn),
			"idle_remaining", dq.idleCountLocked(),
			"pool_size", len(dq.sessions),
		)
		return s, nil
	}

	return nil, ErrNoConnections
}

func remoteAddr(conn net.Conn) any {
	if conn == nil {
		return nil
	}
	return conn.RemoteAddr()
}

// removeSessionLocked removes session from the pool and returns whether it was present.
// Caller must hold dq.mu.
func (dq *DataQueue) removeSessionLocked(session *MuxSession) bool {
	if session == nil {
		return false
	}
	for i, s := range dq.sessions {
		if s == session {
			dq.sessions = append(dq.sessions[:i], dq.sessions[i+1:]...)
			delete(dq.connBySession, s.ID())
			delete(dq.leased, s.ID())
			return true
		}
	}
	delete(dq.connBySession, session.ID())
	delete(dq.leased, session.ID())
	return false
}

// RemoveSession removes a session from the pool (e.g., when its underlying conn dies).
func (dq *DataQueue) RemoveSession(session *MuxSession) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.removeSessionLocked(session) {
		slog.Debug("data queue: removed session", "pool_size", len(dq.sessions))
	}
}

// CloseSession retires a checked-out session and closes its underlying
// connection. Use this after a proxied request completes so the connection
// is never reused for another request.
func (dq *DataQueue) CloseSession(session *MuxSession) {
	dq.mu.Lock()
	removed := dq.removeSessionLocked(session)
	poolSize := len(dq.sessions)
	dq.mu.Unlock()

	if removed {
		slog.Debug("data queue: retiring dedicated session",
			"session_id", session.ID(),
			"pool_size", poolSize,
		)
	}
	if session != nil {
		_ = session.Close()
	}
}

// Size returns the number of sessions currently tracked by the pool.
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

// PoolStats returns total, idle and busy session counts. Idle means the
// session is alive, not checked out, and currently has zero mux streams.
func (dq *DataQueue) PoolStats() (total int, idle int, busy int) {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		total++
		if dq.leased[s.ID()] || s.NumStreams() != 0 {
			busy++
			continue
		}
		idle++
	}
	return total, idle, busy
}

// IdleCount returns the number of available idle sessions.
func (dq *DataQueue) IdleCount() int {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	return dq.idleCountLocked()
}

// idleCountLocked counts idle sessions. Caller must hold dq.mu.
func (dq *DataQueue) idleCountLocked() int {
	idle := 0
	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		if dq.leased[s.ID()] || s.NumStreams() != 0 {
			continue
		}
		idle++
	}
	return idle
}

// CloseIdleExcess closes idle sessions until idle <= maxIdle. Busy sessions
// are never closed by pool trimming.
func (dq *DataQueue) CloseIdleExcess(maxIdle int) int {
	dq.mu.Lock()
	if dq.closed {
		dq.mu.Unlock()
		return 0
	}

	idle := dq.idleCountLocked()
	excess := idle - maxIdle
	if excess <= 0 {
		dq.mu.Unlock()
		return 0
	}

	toClose := make([]*MuxSession, 0, excess)
	kept := dq.sessions[:0]
	for _, s := range dq.sessions {
		if excess > 0 && !s.IsClosed() && !dq.leased[s.ID()] && s.NumStreams() == 0 {
			toClose = append(toClose, s)
			delete(dq.connBySession, s.ID())
			delete(dq.leased, s.ID())
			excess--
			continue
		}
		kept = append(kept, s)
	}
	dq.sessions = kept
	poolSize := len(dq.sessions)
	dq.mu.Unlock()

	for _, s := range toClose {
		slog.Debug("data queue: closing excess idle session",
			"session_id", s.ID(),
			"pool_size", poolSize,
		)
		_ = s.Close()
	}
	return len(toClose)
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
						delete(dq.connBySession, s.ID())
						delete(dq.leased, s.ID())
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
	dq.connBySession = make(map[uint64]net.Conn)
	dq.leased = make(map[uint64]bool)
	dq.mu.Unlock()

	close(dq.pruneDone)

	slog.Debug("data queue: pool closed")
	return firstErr
}

// SessionInfo holds per-session stats for observability logging.
type SessionInfo struct {
	ID      uint64
	Streams int
	Leased  bool
	Idle    bool
	Closed  bool
}

// DetailedStats returns per-session info for periodic logging.
func (dq *DataQueue) DetailedStats() []SessionInfo {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	infos := make([]SessionInfo, len(dq.sessions))
	for i, s := range dq.sessions {
		streams := s.NumStreams()
		leased := dq.leased[s.ID()]
		closed := s.IsClosed()
		infos[i] = SessionInfo{
			ID:      s.ID(),
			Streams: streams,
			Leased:  leased,
			Idle:    !closed && !leased && streams == 0,
			Closed:  closed,
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
