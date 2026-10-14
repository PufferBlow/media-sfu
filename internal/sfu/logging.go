package sfu

import (
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lmittmann/tint"
)

// newLogger logs in colour to a terminal and as plain key=value text
// otherwise (Docker, systemd, log shippers). Unknown levels mean info.
func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	replaceAttr := func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			a.Key = "ts"
		}
		return a
	}

	if isTerminal(os.Stdout) {
		return slog.New(tint.NewHandler(os.Stdout, &tint.Options{
			Level:       slogLevel,
			TimeFormat:  time.DateTime,
			ReplaceAttr: replaceAttr,
		}))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slogLevel,
		ReplaceAttr: replaceAttr,
	}))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}
