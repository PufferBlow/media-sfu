// Command server runs the Pufferblow media SFU.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pufferblow/media-sfu/internal/sfu"
)

func main() {
	configPath := flag.String(
		"config",
		sfu.DefaultConfigPath(),
		"Path to the shared Pufferblow config.toml file",
	)
	flag.Parse()

	server, err := sfu.New(*configPath)
	if err != nil {
		slog.Error("failed to initialise media-sfu", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.Serve(ctx); err != nil {
		slog.Error("media-sfu stopped", "err", err)
		os.Exit(1)
	}
}
