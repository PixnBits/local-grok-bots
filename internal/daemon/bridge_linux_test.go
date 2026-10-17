//go:build linux

package daemon

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/clisession"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestGrokNetGrantAttachesEgressBridge(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	plain, err := app.cliIsolation(store.Bot{ID: "b0"}, "grok", ws, "run-0")
	if err != nil {
		t.Fatal(err)
	}
	if plain.ForwardBin != "" || len(plain.ExtraBinds) != 0 {
		t.Fatalf("bridge without a grant or proxy: %+v", plain.ForwardArgs)
	}
	iso, err := app.cliIsolation(store.Bot{
		ID: "b1", Grants: []string{"net"}, NetAllow: []string{"Allowed.Test."},
	}, "grok", ws, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if iso.ReleaseGate != nil {
		t.Cleanup(iso.ReleaseGate)
	}
	if iso.ForwardBin == "" || !strings.Contains(strings.Join(iso.ForwardArgs, " "), "--http-sock "+clisession.JailEgressSock) {
		t.Fatalf("forward %q %v", iso.ForwardBin, iso.ForwardArgs)
	}
	if strings.Contains(strings.Join(iso.ForwardArgs, " "), "--keep-key") {
		t.Fatal("net-only bridge asked to keep a credential key")
	}
	if envValue(iso.Env, "HTTP_PROXY") != "" || envValue(iso.Env, "HTTPS_PROXY") != "" {
		t.Fatal("proxy env was set before the in-jail forwarder")
	}
	if len(iso.ExtraBinds) != 1 || iso.ExtraBinds[0][1] != clisession.JailEgressSock {
		t.Fatalf("binds %v", iso.ExtraBinds)
	}
	sock := iso.ExtraBinds[0][0]
	st, err := os.Stat(sock)
	if err != nil || filepath.Base(sock) != "sock" || st.Mode().Perm() != 0o600 {
		t.Fatalf("sock %s %v %v", sock, st, err)
	}
	iso.ReleaseGate()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("egress socket left behind: %v", err)
	}
}

func TestGrokEgressBridgeAuditsDeniedLiteral(t *testing.T) {
	dir := t.TempDir()
	app := newCLIApp(t, dir, writeCLIPolicy(t, dir))
	logPath := filepath.Join(dir, "audit.log")
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	app.audit = lg
	ws := filepath.Join(dir, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	iso, err := app.cliIsolation(store.Bot{
		ID: "b1", Grants: []string{"net"}, NetAllow: []string{"allowed.test", "10.1.2.3"},
	}, "grok", ws, "run-9")
	if err != nil {
		t.Fatal(err)
	}
	if iso.ReleaseGate != nil {
		t.Cleanup(iso.ReleaseGate)
	}
	if len(iso.ExtraBinds) != 1 {
		t.Fatalf("binds %v", iso.ExtraBinds)
	}
	sock := iso.ExtraBinds[0][0]
	const marker = "unit-header-marker"
	deny := func(req string) {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, _ := c.Read(buf)
		if !strings.Contains(string(buf[:n]), "403") {
			t.Fatalf("status %q", buf[:n])
		}
	}
	deny("CONNECT 10.1.2.3:443 HTTP/1.1\r\nHost: 10.1.2.3:443\r\nX-Secret: " + marker + "\r\n\r\n")
	deny("CONNECT allowed.test:22 HTTP/1.1\r\nHost: allowed.test:22\r\nX-Secret: " + marker + "\r\n\r\n")
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
		`"bot_id":"b1"`,
		`"run_id":"run-9"`,
		`"host":"10.1.2.3"`,
		`"reason":"address"`,
		`"decision":"deny"`,
		`"host":"allowed.test"`,
		`"port":22`,
		`"reason":"port"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in %s", want, text)
		}
	}
	for _, bad := range []string{marker, "X-Secret", "Authorization"} {
		if strings.Contains(text, bad) {
			t.Fatalf("audit contains %s", bad)
		}
	}
}
