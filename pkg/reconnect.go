package pkg

import (
	"context"
	"log/slog"
	"math"
	"time"
)

const (
	InitialBackoff = 1 * time.Second
	MaxBackoff     = 30 * time.Second
	BackoffFactor  = 2.0
)

// Reconnect repeatedly calls connectFn until it succeeds or ctx is cancelled.
// Uses exponential backoff between attempts.
// Returns nil on success, ctx.Err() on cancellation.
func Reconnect(ctx context.Context, name string, connectFn func() error) error {
	backoff := InitialBackoff
	for {
		err := connectFn()
		if err == nil {
			slog.Info("reconnected", "name", name)
			return nil
		}

		slog.Warn("connection failed, retrying", "name", name, "err", err, "backoff", backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Exponential backoff with cap
		backoff = time.Duration(math.Min(float64(backoff)*BackoffFactor, float64(MaxBackoff)))
	}
}
