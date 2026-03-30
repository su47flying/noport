package client

import (
	"io"
	"net"
	"sync"
	"time"
)

const relayBufSize = 128 << 10 // 128KB

var relayBufPool = sync.Pool{
	New: func() any { return make([]byte, relayBufSize) },
}

// relay copies data bidirectionally between two net.Conn.
// When one direction finishes, the other is terminated promptly.
// Returns (fromB, fromA):
//   - fromB: bytes read from b and written to a
//   - fromA: bytes read from a and written to b
func relay(a, b net.Conn) (fromB int64, fromA int64) {
	done := make(chan struct{})

	go func() {
		buf := relayBufPool.Get().([]byte)
		fromB, _ = io.CopyBuffer(a, b, buf)
		relayBufPool.Put(buf)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			a.SetReadDeadline(time.Now())
		}
		close(done)
	}()

	buf := relayBufPool.Get().([]byte)
	fromA, _ = io.CopyBuffer(b, a, buf)
	relayBufPool.Put(buf)
	if tc, ok := b.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		b.SetReadDeadline(time.Now())
	}

	<-done
	return
}
