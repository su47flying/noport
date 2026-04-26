package pkg

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// RelayDirectionStats describes one direction of a bidirectional relay.
type RelayDirectionStats struct {
	Bytes         int64
	FirstByte     time.Duration
	FirstByteSeen bool
	Result        string
}

// RelayStats describes a full bidirectional relay between two net.Conns.
// AToB is bytes read from a and written to b. BToA is bytes read from b and written to a.
type RelayStats struct {
	AToB     RelayDirectionStats
	BToA     RelayDirectionStats
	Duration time.Duration
}

// Relay copies data bidirectionally between two net.Conns and records per-direction stats.
func Relay(a, b net.Conn, bufPool *sync.Pool) RelayStats {
	start := time.Now()
	aToBDone := make(chan RelayDirectionStats, 1)

	go func() {
		aToBDone <- relayOneWay(b, a, bufPool, start)
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = b.SetReadDeadline(time.Now())
		}
	}()

	bToA := relayOneWay(a, b, bufPool, start)
	if tc, ok := a.(interface{ CloseWrite() error }); ok {
		_ = tc.CloseWrite()
	} else {
		_ = a.SetReadDeadline(time.Now())
	}

	aToB := <-aToBDone
	return RelayStats{
		AToB:     aToB,
		BToA:     bToA,
		Duration: time.Since(start),
	}
}

func relayOneWay(dst, src net.Conn, bufPool *sync.Pool, start time.Time) RelayDirectionStats {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)

	stats := RelayDirectionStats{}
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if nw > 0 {
				stats.Bytes += int64(nw)
				if !stats.FirstByteSeen {
					stats.FirstByteSeen = true
					stats.FirstByte = time.Since(start)
				}
			}
			if writeErr != nil {
				stats.Result = classifyRelayResult(writeErr)
				return stats
			}
			if nw != nr {
				stats.Result = "short_write"
				return stats
			}
		}
		if readErr != nil {
			stats.Result = classifyRelayResult(readErr)
			return stats
		}
	}
}

func classifyRelayResult(err error) string {
	switch {
	case err == nil:
		return "eof"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "deadline"
	default:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "timeout"
		}
		return "error"
	}
}
