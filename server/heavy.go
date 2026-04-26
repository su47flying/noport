package server

import (
	"net"
	"sync/atomic"
)

// PromoteThresholdBytes is the per-stream payload (read+write summed) at
// which the stream's target host is marked heavy. Future streams to the
// same host are then routed onto a dedicated MuxSession so head-of-line
// blocking on the shared pool can no longer stall unrelated traffic.
//
// 2 MiB is past the size of typical control / page-load traffic but small
// enough to react within a single video segment (HLS / DASH typically
// emit 1–4 MiB segments at 1080p). The previous 4 MiB ceiling never
// fired in practice because each segment closes before the threshold.
const PromoteThresholdBytes int64 = 2 << 20

// promoteWatchConn wraps a net.Conn and counts bytes flowing in either
// direction. When the cumulative count first crosses PromoteThresholdBytes
// it invokes onHeavy(host) exactly once. The wrapper is otherwise a
// transparent passthrough — it never alters or buffers payload, so the
// existing pkg.Relay loop is unaffected.
type promoteWatchConn struct {
	net.Conn
	host    string
	onHeavy func(host string)
	bytes   atomic.Int64
	fired   atomic.Bool
}

func newPromoteWatchConn(c net.Conn, host string, onHeavy func(host string)) *promoteWatchConn {
	return &promoteWatchConn{Conn: c, host: host, onHeavy: onHeavy}
}

func (p *promoteWatchConn) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b)
	if n > 0 {
		p.account(int64(n))
	}
	return n, err
}

func (p *promoteWatchConn) Write(b []byte) (int, error) {
	n, err := p.Conn.Write(b)
	if n > 0 {
		p.account(int64(n))
	}
	return n, err
}

func (p *promoteWatchConn) account(n int64) {
	total := p.bytes.Add(n)
	if total >= PromoteThresholdBytes && p.fired.CompareAndSwap(false, true) {
		if p.onHeavy != nil {
			p.onHeavy(p.host)
		}
	}
}

var _ net.Conn = (*promoteWatchConn)(nil)
