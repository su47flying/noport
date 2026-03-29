package main

import (
	"fmt"
	"log/slog"
	"os"

	"noport/cmd"
	_ "noport/crypto"
	"noport/pkg"
)

func main() {
	cfg, err := pkg.ParseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pkg.InitLogger(cfg.Debug)

	slog.Info("noport starting", "mode", modeStr(cfg))

	if cfg.IsClient() {
		if err := cmd.RunClient(cfg); err != nil {
			slog.Error("client error", "err", err)
			os.Exit(1)
		}
	} else if cfg.IsServer() {
		if err := cmd.RunServer(cfg); err != nil {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "No mode specified. Use -C for client or -L/-R for server.\n")
		os.Exit(1)
	}
}

func modeStr(cfg *pkg.Config) string {
	if cfg.IsClient() {
		return "client"
	}
	return "server"
}
