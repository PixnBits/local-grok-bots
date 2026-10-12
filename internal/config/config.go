package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.1.0"

// Config is the daemon's environment. Defaults match the MVP spec:
// SQLite at ./data/state.db, workspace at ./data/workspace, Ollama on localhost.
type Config struct {
	DataDir    string
	BindAddr   string
	OllamaURL  string
	Model      string
	AuthToken  string
	Version    string
	BuildBinds []string
	// CLIBackend is the default model backend for new bots: grok, claude, or empty (Ollama).
	CLIBackend string
}

func FromEnv() Config {
	return Config{
		DataDir:    getenv("DATA_DIR", "./data"),
		BindAddr:   getenv("BIND_ADDR", "127.0.0.1:8080"),
		OllamaURL:  getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
		Model:      getenv("OLLAMA_MODEL", "llama3.2"),
		AuthToken:  os.Getenv("AUTH_TOKEN"),
		Version:    Version,
		BuildBinds: splitList(os.Getenv("SANDBOX_BUILD_BINDS")),
		CLIBackend: strings.ToLower(strings.TrimSpace(os.Getenv("CLI_BACKEND"))),
	}
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, string(os.PathListSeparator)) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c Config) DBPath() string {
	return filepath.Join(c.DataDir, "state.db")
}

func (c Config) Workspace() string {
	return filepath.Join(c.DataDir, "workspace")
}

// Validate rejects a non-loopback bind that has no AUTH_TOKEN.
// An empty host, as in ":8080", listens on all interfaces.
func (c Config) Validate() error {
	host, _, err := net.SplitHostPort(c.BindAddr)
	if err != nil {
		return fmt.Errorf("BIND_ADDR: %w", err)
	}
	if loopbackHost(host) {
		return nil
	}
	if strings.TrimSpace(c.AuthToken) == "" {
		return fmt.Errorf("AUTH_TOKEN is required when BIND_ADDR is not loopback (%s)", c.BindAddr)
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
