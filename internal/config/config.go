package config

import (
	"os"
	"path/filepath"
	"strings"
)

const Version = "0.1.0"

// Config is the daemon's environment. Defaults match the MVP spec:
// SQLite at ./data/state.db, workspace at ./data/workspace, Ollama on localhost.
type Config struct {
	DataDir        string
	BindAddr       string
	OllamaURL      string
	Model          string
	AuthToken      string
	AuthTokensFile string
	Version        string
	BuildBinds     []string
	// PolicyPath is the policy.toml to load. Empty skips the file and keeps
	// built-in defaults. The daemon sets this to "policy.toml" unless POLICY_PATH is set.
	PolicyPath string
	// TLSCert and TLSKey are a pair. TLSSelfSigned generates a cert under DATA_DIR/tls.
	// Policy [daemon] tls_* replaces these.
	TLSCert       string
	TLSKey        string
	TLSSelfSigned bool
	// WhisperBin and WhisperModel are the local whisper-cli and model.
	// Both empty leaves speech recognition unconfigured. Policy [voice] replaces these.
	WhisperBin   string
	WhisperModel string
	// PermCallbackAddr is the loopback plain-HTTP permission callback.
	// Empty means 127.0.0.1:0. Policy replaces this.
	PermCallbackAddr string
}

func FromEnv() Config {
	tok := heldAuth
	if tok == "" {
		tok = os.Getenv("AUTH_TOKEN")
	}
	tokensFile := heldTokensFile
	if tokensFile == "" {
		tokensFile = os.Getenv("AUTH_TOKENS_FILE")
	}
	return Config{
		DataDir:          getenv("DATA_DIR", "./data"),
		BindAddr:         getenv("BIND_ADDR", "127.0.0.1:8080"),
		OllamaURL:        getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
		Model:            getenv("OLLAMA_MODEL", "llama3.2"),
		AuthToken:        tok,
		AuthTokensFile:   tokensFile,
		Version:          Version,
		BuildBinds:       splitList(os.Getenv("SANDBOX_BUILD_BINDS")),
		PolicyPath:       getenv("POLICY_PATH", "policy.toml"),
		TLSCert:          os.Getenv("TLS_CERT"),
		TLSKey:           CurrentTLSKey(),
		TLSSelfSigned:    os.Getenv("TLS_SELF_SIGNED") == "1",
		WhisperBin:       os.Getenv("WHISPER_BIN"),
		WhisperModel:     os.Getenv("WHISPER_MODEL"),
		PermCallbackAddr: os.Getenv("PERM_CALLBACK_ADDR"),
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

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
