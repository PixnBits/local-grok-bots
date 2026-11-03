package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestShellEgressHeaderAndBusyAudit(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	app.audit = lg
	app.recordSandboxEvents("bot_hdr", []sandbox.Event{{
		Kind: "grant_denied", Detail: "header",
	}})
	app.recordSandboxEvents("bot_busy", []sandbox.Event{{
		Kind: "grant_denied", Detail: "busy",
	}})
	raw := readAudit(t, auditPath)
	if strings.Count(raw, `"action":"grant_denied"`) != 2 {
		t.Fatalf("audit:\n%s", raw)
	}
	if !strings.Contains(raw, `"detail":"header"`) || !strings.Contains(raw, `"detail":"busy"`) {
		t.Fatalf("audit:\n%s", raw)
	}
	if strings.Contains(raw, `"bot_id":"bot_hdr"`) && !strings.Contains(raw, "header") {
		t.Fatalf("audit:\n%s", raw)
	}
}
