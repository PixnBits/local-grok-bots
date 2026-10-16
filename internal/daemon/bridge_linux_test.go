//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
