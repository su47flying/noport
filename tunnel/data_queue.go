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
//
// Sessions may be *reserved* for a specific heavy host (see GetSessionForTarget).
// A reserved session is excluded from the shared least-loaded picker so
// unrelated streams don't pile onto a session dedicated to a high-bandwidth
// target (e.g. video CDN).
type DataQueue struct {
	mu        sync.RWMutex
	sessions  []*MuxSession
	cipher    crypto.Cipher
	closed    bool
	isServer  bool
	pruneDone chan struct{}

	// reservations maps session ID -> host the session is reserved for.
	// Entries are cleared lazily when the session dies (prune) or when
	// the reservation is released explicitly.
	reservations map[uint64]string
}

// NewDataQueue creates a new data queue pool.
// cipher can be nil for no encryption.
func NewDataQueue(cipher crypto.Cipher, isServer bool) *DataQueue {
	dq := &DataQueue{
		cipher:       cipher,
		isServer:     isServer,
		pruneDone:    make(chan struct{}),
		reservations: make(map[uint64]string),
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
//
// Sessions reserved for a specific heavy host are excluded from selection
// so unrelated traffic doesn't pollute them.
//
// Skips closed sessions. Returns error if pool is empty or closed.
func (dq *DataQueue) GetSession() (*MuxSession, error) {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	return dq.pickLocked("", false)
}

// GetSessionForTarget returns a MuxSession suitable for a stream to
// `target` (host:port form). When `hh` indicates the target's host is
// heavy, the queue isolates the stream by:
//  1. returning the session already reserved for that host if it's still
//     alive, OR
//  2. promoting the least-loaded shared session to a per-host reservation
//     and returning it.
//
// Either way, future *non-heavy* GetSession()/GetSessionForTarget() calls
// will skip that session, which prevents head-of-line blocking on the
// shared pool. The reservation persists until the session dies (pruned)
// or until the host's heavy mark expires AND the queue is asked to
// recompute via ReleaseExpiredReservations.
//
// Falls back to the regular least-loaded picker if hh is nil or the host
// is not heavy. Returns the second value `reserved=true` iff the session
// was selected via a host reservation (for caller logging).
func (dq *DataQueue) GetSessionForTarget(target string, hh *HeavyHostSet) (*MuxSession, bool, error) {
	host := HostOnly(target)
	heavy := hh != nil && host != "" && hh.IsHeavy(host)

	if !heavy {
		dq.mu.RLock()
		s, err := dq.pickLocked("", false)
		dq.mu.RUnlock()
		return s, false, err
	}

	// Heavy path needs the write lock because we may mutate reservations.
	dq.mu.Lock()
	defer dq.mu.Unlock()

	if dq.closed {
		return nil, false, ErrPoolClosed
	}

	// 1. Existing reservation for this host?
	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		if dq.reservations[s.ID()] == host {
			slog.Debug("data queue: reused dedicated session",
				"session_id", s.ID(),
				"host", host,
				"streams", s.NumStreams(),
				"inflight_bytes", s.InflightBytes(),
			)
			return s, true, nil
		}
	}

	// 2. Promote a fresh session: pick the least-loaded *unreserved* one
	// and reserve it for this host. Avoids stealing a session that's
	// already pinned to another heavy host.
	best, err := dq.pickLockedUnreserved()
	if err != nil {
		return nil, false, err
	}
	dq.reservations[best.ID()] = host
	slog.Info("data queue: dedicated session reserved for heavy host",
		"session_id", best.ID(),
		"host", host,
		"pool_size", len(dq.sessions),
	)
	return best, true, nil
}

// pickLocked picks the least-loaded session. Caller must hold mu.
// If reservedOK is false, sessions reserved for any host are skipped.
// If reservedOK is true and host is non-empty, only sessions reserved
// for that host (or unreserved) are considered (used internally; not
// currently invoked from outside).
func (dq *DataQueue) pickLocked(host string, reservedOK bool) (*MuxSession, error) {
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
		if !reservedOK {
			if r, ok := dq.reservations[s.ID()]; ok && r != host {
				continue
			}
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

// pickLockedUnreserved returns the least-loaded session that has no
// existing reservation. Caller must hold mu (write or read).
func (dq *DataQueue) pickLockedUnreserved() (*MuxSession, error) {
	var best *MuxSession
	var bestInflight int64
	var bestStreams int

	for _, s := range dq.sessions {
		if s.IsClosed() {
			continue
		}
		if _, reserved := dq.reservations[s.ID()]; reserved {
			continue
		}
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
	return best, nil
}

// HostOnly returns the host portion of a "host:port" target. Falls back
// to the input if no port separator is present. IPv6 brackets are
// preserved.
func HostOnly(target string) string {
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == ':' {
			return target[:i]
		}
		if target[i] == ']' {
			// Avoid splitting inside an IPv6 literal "[::1]:443" — the
			// closing bracket guards against the wrong colon.
			return target[:i+1]
		}
	}
	return target
}

// RemoveSession removes a session from the pool (e.g., when its underlying conn dies).
func (dq *DataQueue) RemoveSession(session *MuxSession) {
	dq.mu.Lock()
	defer dq.mu.Unlock()

	for i, s := range dq.sessions {
		if s == session {
			dq.sessions = append(dq.sessions[:i], dq.sessions[i+1:]...)
			delete(dq.reservations, s.ID())
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
						delete(dq.reservations, s.ID())
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
	ID          uint64
	Streams     int
	Inflight    int64
	Closed      bool
	ReservedFor string // empty when session is in the shared pool
}

// DetailedStats returns per-session info for periodic logging.
func (dq *DataQueue) DetailedStats() []SessionInfo {
	dq.mu.RLock()
	defer dq.mu.RUnlock()
	infos := make([]SessionInfo, len(dq.sessions))
	for i, s := range dq.sessions {
		infos[i] = SessionInfo{
			ID:          s.ID(),
			Streams:     s.NumStreams(),
			Inflight:    s.InflightBytes(),
			Closed:      s.IsClosed(),
			ReservedFor: dq.reservations[s.ID()],
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

// ReleaseExpiredReservations drops reservations whose host is no longer
// marked heavy in hh, returning a sessions back into the shared pool.
// Safe to call periodically from a maintenance goroutine.
func (dq *DataQueue) ReleaseExpiredReservations(hh *HeavyHostSet) {
	if hh == nil {
		return
	}
	dq.mu.Lock()
	for sid, host := range dq.reservations {
		if !hh.IsHeavy(host) {
			delete(dq.reservations, sid)
			slog.Info("data queue: released dedicated session",
				"session_id", sid,
				"host", host,
				"reason", "heavy mark expired",
			)
		}
	}
	dq.mu.Unlock()
}
