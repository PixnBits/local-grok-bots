//go:build linux

package sandbox

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetWrapDoesNotRunUntilReady(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap unavailable")
	}
	root := t.TempDir()
	lgb := filepath.Join(root, "lgb")
	bin := filepath.Join(lgb, "bin")
	sockDir := filepath.Join(lgb, "sock")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nif [ \"$1\" = probe ]; then\n  exit 1\nfi\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(bin, "netbridge"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(sockDir, "egress.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	script := filepath.Join(root, "netwrap")
	if err := os.WriteFile(script, []byte(netWrapScript()), 0o755); err != nil {
		t.Fatal(err)
	}
	markerDir := filepath.Join(root, "marker")
	if err := os.MkdirAll(markerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A private root so bubblewrap can create /lgb without writing to the host /.
	jail := filepath.Join(root, "root")
	for _, dir := range []string{"tmp", "lgb", "marker", "proc", "dev", "bin", "usr", "lib", "lib64", "etc"} {
		if err := os.MkdirAll(filepath.Join(jail, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scriptInJail := filepath.Join(jail, "netwrap")
	if err := os.Rename(script, scriptInJail); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--die-with-parent",
		"--bind", jail, "/",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
	}
	if st, statErr := os.Stat("/lib64"); statErr == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}
	args = append(args,
		"--ro-bind", "/etc", "/etc",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", lgb, "/lgb",
		"--bind", markerDir, "/marker",
		"--",
		"/bin/sh", "/netwrap", "/bin/sh", "-c", "echo RAN > /marker/ran",
	)
	cmd := exec.Command("bwrap", args...)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if _, statErr := os.Stat(filepath.Join(markerDir, "ran")); !os.IsNotExist(statErr) {
		t.Fatalf("command ran after %s: %v\n%s", elapsed, err, out)
	}
	if !strings.Contains(string(out), "network proxy unavailable") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	// The readiness loop waits about five seconds. An earlier exit never reached it.
	if elapsed < 4*time.Second {
		t.Fatalf("exited before the readiness wait: %s\n%s", elapsed, out)
	}
}
