package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestAuditSandboxGitHubDenial(t *testing.T) {
	app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Host: "github.com", Detail: sandbox.GitHubNetworkDenied,
	})
	app.recordSandbox("bot_1", sandbox.Event{
		Kind: "grant_denied", Grant: "github", Detail: sandbox.GitHubProxyDenied,
	})
	app.recordSandbox("bot_1", sandbox.Event{Kind: "grant_denied", Grant: "net", Detail: "no"})
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"github_refuse"`) != 2 || !strings.Contains(raw, sandbox.GitHubNetworkDenied) || !strings.Contains(raw, sandbox.GitHubProxyDenied) {
		t.Fatalf("audit:\n%s", raw)
	}
	if !strings.Contains(raw, `"decision":"deny"`) || !strings.Contains(raw, `"host":"github.com"`) {
		t.Fatalf("audit fields:\n%s", raw)
	}
	if strings.Contains(raw, "github_refuse") && strings.Contains(raw, `"grant":"net"`) && strings.Count(raw, "github_refuse") != 2 {
		t.Fatalf("net denial audited as github:\n%s", raw)
	}
}
