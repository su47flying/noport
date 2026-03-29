package client

import (
	"io"
	"log/slog"
	"net"
	"time"
)

// relay copies data bidirectionally between two net.Conn.
// When one direction finishes, the other is terminated promptly.
func relay(a, b net.Conn) {
	done := make(chan struct{})

	go func() {
		_, err := io.Copy(a, b)
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

	_, err := io.Copy(b, a)
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
