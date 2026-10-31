package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

func TestGolden_ClassifierConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
`)
	p, err := Load(Options{Path: path})
	if err != nil || p.ClassifierEnabled || p.ClassifierEndpoint != "" {
		t.Fatalf("default err=%v enabled=%v endpoint=%q", err, p.ClassifierEnabled, p.ClassifierEndpoint)
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
[cli.permission.classifier]
enabled = false
endpoint = "http://example.com/classify"
`)
	if _, err := Load(Options{Path: path}); !errors.Is(err, permbroker.ErrClassifierEndpoint) {
		t.Fatalf("public endpoint %v", err)
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
[cli.permission.classifier]
enabled = true
endpoint = "http://127.0.0.1:9/classify"
model = "local"
`)
	p, err = Load(Options{Path: path})
	if err != nil || !p.ClassifierEnabled || p.ClassifierEndpoint != "http://127.0.0.1:9/classify" || p.ClassifierModel != "local" || p.ClassifierTimeout != 4*time.Second {
		t.Fatalf("err=%v %+v", err, p)
	}
	write(`
[backend]
backend = "ollama"
[cli.permission]
broker = "hook"
[cli.permission.classifier]
enabled = true
endpoint = "http://192.168.0.2/classify"
`)
	if _, err := Load(Options{Path: path}); !errors.Is(err, permbroker.ErrClassifierEndpoint) {
		t.Fatalf("lan %v", err)
	}
}
