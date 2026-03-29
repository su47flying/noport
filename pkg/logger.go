package pkg

import (
	"log/slog"
	"os"
)

// InitLogger sets up the global slog logger.
// If debug is true, set level to Debug; otherwise Info.
// Use text handler writing to stderr with source info in debug mode.
func InitLogger(debug bool) {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: debug,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(handler))
}
