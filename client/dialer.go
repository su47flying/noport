package client

import (
	"io"
	"log/slog"
	"net"
	"sync"
)

const relayBufSize = 128 << 10 // 128KB

var relayBufPool = sync.Pool{
	New: func() any { return make([]byte, relayBufSize) },
}

// relay copies data bidirectionally between two net.Conn (gost transport pattern).
// Two goroutines copy independently. When the first direction finishes,
// both connections are closed to unblock the other direction.
// Caller's deferred Close() calls are safe (idempotent).
// Returns (fromB, fromA):
//   - fromB: bytes read from b and written to a
//   - fromA: bytes read from a and written to b
func relay(a, b net.Conn) (fromB int64, fromA int64) {
	ch := make(chan struct{}, 2)
	var errB, errA error

	// b → a
	go func() {
		buf := relayBufPool.Get().([]byte)
		fromB, errB = io.CopyBuffer(a, b, buf)
		relayBufPool.Put(buf)
		ch <- struct{}{}
	}()

	// a → b
	go func() {
		buf := relayBufPool.Get().([]byte)
		fromA, errA = io.CopyBuffer(b, a, buf)
		relayBufPool.Put(buf)
		ch <- struct{}{}
	}()

	// Wait for first direction to complete, then close both to unblock the other
	<-ch
	a.Close()
	b.Close()
	<-ch

	if errB != nil && errB != io.EOF {
		slog.Debug("relay from-target error", "err", errB, "bytes", fromB)
	}
	if errA != nil && errA != io.EOF {
		slog.Debug("relay to-target error", "err", errA, "bytes", fromA)
	}
	return
}
