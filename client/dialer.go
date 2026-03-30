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
// Returns bytes transferred in each direction.
func relay(a, b net.Conn) (aToB int64, bToA int64) {
	done := make(chan struct{})

	go func() {
		buf := relayBufPool.Get().([]byte)
		aToB, _ = io.CopyBuffer(a, b, buf)
		relayBufPool.Put(buf)
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			a.SetReadDeadline(time.Now())
		}
		close(done)
	}()

	buf := relayBufPool.Get().([]byte)
	bToA, _ = io.CopyBuffer(b, a, buf)
	relayBufPool.Put(buf)
	if tc, ok := b.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		b.SetReadDeadline(time.Now())
	}

	<-done
	return
}
