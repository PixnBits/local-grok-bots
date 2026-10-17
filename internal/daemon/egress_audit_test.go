package daemon

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func TestEgressAuditRecordOmitsRequest(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	const marker = "unit-header-marker"
	p, err := sandbox.StartHTTPAllowProxy(filepath.Join(dir, "cli-egress"), sandbox.EgressConfig{
		Allow: []string{"allowed.test"},
		Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, io.EOF
		},
		Audit: func(ev sandbox.EgressEvent) {
			app.auditEgress("bot-1", "run-1", ev)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := net.Dial("unix", p.Sock())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET http://allowed.test/ok HTTP/1.1\r\nHost: allowed.test\r\nX-Secret: "+marker+"\r\n\r\n"+marker)
	_, _ = io.ReadAll(c)
	_ = c.Close()
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		`"event":"cli_egress_request"`,
		`"bot_id":"bot-1"`,
		`"run_id":"run-1"`,
		`"host":"allowed.test"`,
		`"port":80`,
		`"decision":"deny"`,
		`"reason":"dial"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	for _, bad := range []string{marker, "X-Secret", "Authorization", "GET /ok"} {
		if strings.Contains(text, bad) {
			t.Fatalf("audit contains %s in %s", bad, text)
		}
	}
}
