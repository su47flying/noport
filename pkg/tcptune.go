package pkg

import (
	"log/slog"
	"net"
	"time"
)

// dataKeepAlivePeriod is the interval between TCP keepalive probes on
// long-lived data connections. Tuned aggressively (vs. the OS default of
// ~2 hours) so a silently dead path is detected within roughly one minute,
// which matches the mux write deadline and prevents stuck conn.Write from
// dragging unrelated streams.
const dataKeepAlivePeriod = 30 * time.Second

// TuneDataConn applies socket options appropriate for noport's long-lived
// multiplexed data TCP connections:
//   - TCP_NODELAY:  small mux frames (16KB) must hit the wire immediately;
//     otherwise Nagle batches them with the next frame and adds RTT-scale
//     latency to interactive streams sharing a session.
//   - SO_KEEPALIVE:  detect NAT timeouts and silently dead links rather
//     than discovering the failure only when conn.Write blocks indefinitely.
//
// It is safe to call on any net.Conn; non-TCP conns are silently ignored
// (this happens in tests using net.Pipe).
func TuneDataConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tc.SetNoDelay(true); err != nil {
		slog.Debug("tcp tune: set nodelay failed", "err", err)
	}
	if err := tc.SetKeepAlive(true); err != nil {
		slog.Debug("tcp tune: set keepalive failed", "err", err)
		return
	}
	if err := tc.SetKeepAlivePeriod(dataKeepAlivePeriod); err != nil {
		slog.Debug("tcp tune: set keepalive period failed", "err", err)
	}
}
