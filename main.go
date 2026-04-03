package main

import (
	"fmt"
	"log/slog"
	"os"

	"noport/cmd"
	_ "noport/crypto"
	"noport/pkg"
)

// Set via -ldflags at build time, defaults to "dev"
var version = "0.0.1"

func main() {
	// Handle -version before flag.Parse (which happens in ParseConfig)
	for _, arg := range os.Args[1:] {
		if arg == "-version" || arg == "--version" || arg == "-v" {
			fmt.Printf("noport version %s\n", version)
			os.Exit(0)
		}
	}

	cfg, err := pkg.ParseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pkg.InitLogger(cfg.Debug)

	slog.Info("noport starting", "version", version, "mode", modeStr(cfg))

	if cfg.IsClient() {
		if err := cmd.RunClient(cfg); err != nil {
			slog.Error("client error", "err", err)
			os.Exit(1)
		}
	} else if cfg.IsForwarder() {
		if err := cmd.RunForwarder(cfg); err != nil {
			slog.Error("forwarder error", "err", err)
			os.Exit(1)
		}
	} else if cfg.IsServer() {
		if err := cmd.RunServer(cfg); err != nil {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "No mode specified. Use -C for client, -L/-R for server, or -L/-F for forwarder.\n")
		os.Exit(1)
	}
}

func modeStr(cfg *pkg.Config) string {
	if cfg.IsClient() {
		return "client"
	}
	if cfg.IsForwarder() {
		return "forwarder"
	}
	return "server"
}
