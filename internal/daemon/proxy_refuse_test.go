package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
)

func TestProbeRequestAuditLabel(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.auditProxyRequest("", "", "/", 403, 0, "probe")
	app.auditProxyRequest("b1", "run-1", "/v1/ping", 403, 0, "")
	app.auditProxyRequest("", "", "/admin", 403, 0, "not-a-probe")
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, `"reason":"probe"`) != 1 || strings.Contains(text, "not-a-probe") {
		t.Fatalf("audit %s", text)
	}
	if !strings.Contains(text, `"path":"/"`) || !strings.Contains(text, `"path":"/v1/ping"`) || !strings.Contains(text, `"path":"/admin"`) {
		t.Fatalf("audit %s", text)
	}
}

func TestProxyRefusalAudit(t *testing.T) {
	dir := t.TempDir()
	app := newApp(t, dir, nil)
	auditPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	app.auditProxyRefused("b1", "run-1", "/v1/responses", "server_tool")
	app.auditProxyRefused("b1", "run-1", "/v1/responses", "duplicate_key")
	app.auditProxyRefused("b1", "run-1", "/v1/responses", "not-a-reason")
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "web_search") || strings.Contains(text, "x_search") || strings.Contains(text, "not-a-reason") {
		t.Fatalf("audit %s", text)
	}
	if strings.Count(text, "cli_proxy_refused") != 3 || strings.Count(text, `"reason":"server_tool"`) != 2 || strings.Count(text, `"reason":"duplicate_key"`) != 1 {
		t.Fatalf("audit %s", text)
	}
	if !strings.Contains(text, `"path":"/v1/responses"`) || !strings.Contains(text, `"bot_id":"b1"`) {
		t.Fatalf("audit %s", text)
	}
}
