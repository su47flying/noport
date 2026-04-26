package tunnel

import (
	"log/slog"
	"sync"
	"time"
)

// HeavyHostSet tracks targets whose past streams have transferred enough
// payload to qualify them as "heavy" (e.g. video/CDN). The DataQueue uses
// this to isolate future streams to those targets onto a dedicated
// MuxSession, preventing head-of-line blocking on the shared pool.
//
// Marks expire after TTL so a target that goes quiet eventually rejoins
// the shared pool. The cleanup is opportunistic — IsHeavy() validates
// expiry on each query, and a background goroutine prunes the map.
type HeavyHostSet struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]time.Time

	stop chan struct{}
}

// NewHeavyHostSet creates a HeavyHostSet with the given TTL. The caller
// should defer Close() to stop the background pruner.
func NewHeavyHostSet(ttl time.Duration) *HeavyHostSet {
	hh := &HeavyHostSet{
		ttl:  ttl,
		m:    make(map[string]time.Time),
		stop: make(chan struct{}),
	}
	go hh.pruneLoop()
	return hh
}

// Mark records (or refreshes) host as heavy. Subsequent IsHeavy(host)
// returns true until ttl elapses without a refresh.
func (h *HeavyHostSet) Mark(host string) {
	if host == "" {
		return
	}
	h.mu.Lock()
	_, existed := h.m[host]
	h.m[host] = time.Now()
	h.mu.Unlock()
	if !existed {
		slog.Info("host marked heavy", "host", host, "ttl", h.ttl)
	}
}

// IsHeavy reports whether host is currently marked heavy.
func (h *HeavyHostSet) IsHeavy(host string) bool {
	if host == "" {
		return false
	}
	h.mu.RLock()
	t, ok := h.m[host]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Since(t) > h.ttl {
		// Lazy expiry — drop on read so readers don't observe stale.
		h.mu.Lock()
		if t2, ok := h.m[host]; ok && time.Since(t2) > h.ttl {
			delete(h.m, host)
		}
		h.mu.Unlock()
		return false
	}
	return true
}

// Snapshot returns a copy of currently-heavy hosts (for diagnostics).
func (h *HeavyHostSet) Snapshot() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]string, 0, len(h.m))
	now := time.Now()
	for host, t := range h.m {
		if now.Sub(t) <= h.ttl {
			out = append(out, host)
		}
	}
	return out
}

// Close stops the background pruner.
func (h *HeavyHostSet) Close() {
	select {
	case <-h.stop:
	default:
		close(h.stop)
	}
}

func (h *HeavyHostSet) pruneLoop() {
	// Prune at half the TTL so stale entries vanish promptly.
	interval := h.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			h.prune()
		case <-h.stop:
			return
		}
	}
}

func (h *HeavyHostSet) prune() {
	now := time.Now()
	h.mu.Lock()
	for host, ts := range h.m {
		if now.Sub(ts) > h.ttl {
			delete(h.m, host)
		}
	}
	h.mu.Unlock()
}
