package client

import (
	"io"
	"log/slog"
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
func relay(a, b net.Conn) {
	done := make(chan struct{})

	go func() {
		buf := relayBufPool.Get().([]byte)
		_, err := io.CopyBuffer(a, b, buf)
		relayBufPool.Put(buf)
		if err != nil {
			slog.Debug("relay copy error", "err", err)
		}
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			tc.CloseWrite()
		} else {
			a.SetReadDeadline(time.Now())
		}
		close(done)
	}()

	buf := relayBufPool.Get().([]byte)
	_, err := io.CopyBuffer(b, a, buf)
	relayBufPool.Put(buf)
	if err != nil {
		slog.Debug("relay copy error", "err", err)
	}
	if tc, ok := b.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	} else {
		b.SetReadDeadline(time.Now())
	}

	<-done
}
