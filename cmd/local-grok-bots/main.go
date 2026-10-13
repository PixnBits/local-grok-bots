package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/daemon"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func main() {
	if sandbox.HandleArgs(os.Args[1:]) {
		return
	}
	if err := refuseRoot(os.Geteuid()); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
	cfg := config.FromEnv()
	app, err := daemon.New(cfg, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(os.Stderr, "local-grok-bots %s listening on %s\n", cfg.Version, cfg.BindAddr)
	fmt.Fprintf(os.Stderr, "local-grok-bots policy %s\n", app.PolicyLine())
	if err := app.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
}

// refuseRoot rejects a root daemon. The system unit sets User=local-grok-bots.
func refuseRoot(euid int) error {
	if euid == 0 {
		return fmt.Errorf("refusing to run as root; run as the local-grok-bots user")
	}
	return nil
}
