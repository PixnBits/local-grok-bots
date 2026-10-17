package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PixnBits/local-grok-bots/internal/coi"
	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/daemon"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func main() {
	if coi.HandleForward(os.Args[1:]) {
		return
	}
	if sandbox.HandleArgs(os.Args[1:]) {
		return
	}
	config.ReexecIfNeeded()
	cfg := config.FromEnv()
	app, err := daemon.New(cfg, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "local-grok-bots %s listening on %s\n", cfg.Version, cfg.BindAddr)
	if err := app.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
}
