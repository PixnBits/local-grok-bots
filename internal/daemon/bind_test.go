package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
)

func TestPolicyBindOverridesLoopbackDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte("[daemon]\nbind = \"0.0.0.0:8080\"\ntls_self_signed = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BIND_ADDR", "")
	cfg := config.Config{
		DataDir:    filepath.Join(dir, "data"),
		BindAddr:   "127.0.0.1:8080",
		OllamaURL:  "http://127.0.0.1:9",
		Model:      "test-model",
		Version:    "0.1.0",
		PolicyPath: path,
		AuthToken:  "bind-override-token-bind-override",
	}
	app, err := New(cfg, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.cfg.BindAddr != "0.0.0.0:8080" {
		t.Fatalf("bind %s", app.cfg.BindAddr)
	}
}
