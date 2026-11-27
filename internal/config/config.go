package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	// Think and NumCtx are the lowest chat-option layer. Policy and the bot
	// override them. A nil Think and a zero NumCtx are unset.
	Think  *bool
	NumCtx int
	// modelEnvErr is a bad OLLAMA_THINK or OLLAMA_NUM_CTX. Flags are separate.
	modelEnvErr error
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
	cfg := Config{
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
	think, num, err := parseModelEnv(os.Getenv("OLLAMA_THINK"), os.Getenv("OLLAMA_NUM_CTX"))
	if err != nil {
		cfg.modelEnvErr = err
	} else {
		cfg.Think = think
		cfg.NumCtx = num
	}
	return cfg
}

// ModelEnvError is a bad OLLAMA_THINK or OLLAMA_NUM_CTX value.
func (c Config) ModelEnvError() error {
	return c.modelEnvErr
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

func parseModelEnv(thinkRaw, numRaw string) (*bool, int, error) {
	var think *bool
	if strings.TrimSpace(thinkRaw) != "" {
		v, err := parseBoolFlag(thinkRaw)
		if err != nil {
			return nil, 0, fmt.Errorf("OLLAMA_THINK: %w", err)
		}
		think = &v
	}
	num := 0
	if strings.TrimSpace(numRaw) != "" {
		n, err := parseNumCtxFlag(numRaw)
		if err != nil {
			return nil, 0, fmt.Errorf("OLLAMA_NUM_CTX: %w", err)
		}
		num = n
	}
	return think, num, nil
}

func parseBoolFlag(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("think must be true or false")
	}
}

func parseNumCtxFlag(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > (1<<20) {
		return 0, fmt.Errorf("num_ctx must be from 1 to %d", 1<<20)
	}
	return n, nil
}

// ApplyModelArgs reads --think, --no-think, --think=true|false, and
// --num-ctx. A flag overrides OLLAMA_THINK and OLLAMA_NUM_CTX. Other
// arguments are left alone.
func ApplyModelArgs(cfg Config, args []string) (Config, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--think":
			v := true
			cfg.Think = &v
		case a == "--no-think":
			v := false
			cfg.Think = &v
		case strings.HasPrefix(a, "--think="):
			v, err := parseBoolFlag(strings.TrimPrefix(a, "--think="))
			if err != nil {
				return cfg, err
			}
			cfg.Think = &v
		case a == "--num-ctx":
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("--num-ctx requires a value")
			}
			i++
			n, err := parseNumCtxFlag(args[i])
			if err != nil {
				return cfg, err
			}
			cfg.NumCtx = n
		case strings.HasPrefix(a, "--num-ctx="):
			n, err := parseNumCtxFlag(strings.TrimPrefix(a, "--num-ctx="))
			if err != nil {
				return cfg, err
			}
			cfg.NumCtx = n
		}
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
