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

const usage = `local-grok-bots is a local daemon for a personal bot roster.

  DATA_DIR              ./data
  BIND_ADDR             127.0.0.1:8080
  POLICY_PATH           policy.toml
  OLLAMA_URL            http://127.0.0.1:11434
  OLLAMA_MODEL          llama3.2
  AUTH_TOKEN            unset
  AUTH_TOKENS_FILE      unset
  SANDBOX_BUILD_BINDS   unset

A policy.toml bind overrides BIND_ADDR.
AUTH_TOKENS_FILE is a file of name:token lines and is read at startup.
`

func main() {
	if wantsHelp(os.Args[1:]) {
		fmt.Fprint(os.Stdout, usage)
		os.Exit(0)
	}
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
	if err := app.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots:", err)
		os.Exit(1)
	}
}

func wantsHelp(args []string) bool {
	for _, a := range args[:min(len(args), 1)] {
		switch a {
		case "-h", "--help", "-help":
			return true
		}
	}
	return false
}
