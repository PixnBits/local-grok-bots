//go:build linux

package sandbox

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreloadHandshakeTimesOut(t *testing.T) {
	t.Parallel()
	skipIfMissing(t, "gcc", "bwrap", "python3")
	body, err := ensurePreload()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	so := filepath.Join(dir, "preload.so")
	if err := os.WriteFile(so, body, 0o755); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "proxy.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	script := `import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(30)
t = time.time()
try:
    s.connect(("example.com", 80))
    print("OPEN %.3f" % (time.time()-t))
except OSError as e:
    print("FAIL %.3f %s" % (time.time()-t, type(e).__name__))
`
	cmd := exec.Command("bwrap", "--unshare-net", "--die-with-parent", "--dev-bind", "/", "/", "--", "python3", "-c", script)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+so, "LGB_PROXY_SOCK="+sock)
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	text := string(out)
	if !strings.Contains(text, "FAIL") || strings.Contains(text, "OPEN") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, text)
	}
	if elapsed >= 16*time.Second {
		t.Fatalf("handshake took %s\n%s", elapsed, text)
	}
	if elapsed < 9*time.Second {
		t.Fatalf("handshake returned too fast: %s\n%s", elapsed, text)
	}
}
