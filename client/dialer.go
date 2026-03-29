package client

import (
	"io"
	"log/slog"
	"net"
	"sync"
)

// relay copies data bidirectionally between two net.Conn.
// Blocks until both directions are done.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyFn := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			slog.Debug("relay copy error", "err", err)
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copyFn(a, b)
	go copyFn(b, a)
	wg.Wait()
}
