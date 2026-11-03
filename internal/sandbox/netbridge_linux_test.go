//go:build linux

package sandbox

import (
	"bufio"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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

func TestNetBridgeResetReleasesUnix(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip(err)
	}
	binBytes, err := ensureNetBridge()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "nb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	var open atomic.Int32
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
			open.Add(1)
			go func(c net.Conn) {
				defer open.Add(-1)
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()
	port := freeLocalPort(t)
	bin := filepath.Join(dir, "netbridge")
	if err := os.WriteFile(bin, binBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, strconv.Itoa(port), sock)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		br := bufio.NewReader(stdout)
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			ready <- rerr
			return
		}
		if strings.TrimSpace(line) != "ready" {
			ready <- errReady(line)
			return
		}
		ready <- nil
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("netbridge did not become ready")
	}
	addr := "127.0.0.1:" + strconv.Itoa(port)
	conns := make([]net.Conn, 0, 128)
	deadline := time.Now().Add(5 * time.Second)
	for len(conns) < 128 && time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, time.Second)
		if derr != nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if _, werr := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); werr != nil {
			_ = c.Close()
			continue
		}
		conns = append(conns, c)
	}
	if len(conns) != 128 {
		t.Fatalf("dialed %d", len(conns))
	}
	waitDeadline := time.Now().Add(5 * time.Second)
	for open.Load() < 128 && time.Now().Before(waitDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if open.Load() != 128 {
		t.Fatalf("stub open %d", open.Load())
	}
	for _, c := range conns {
		tcp, ok := c.(*net.TCPConn)
		if !ok {
			t.Fatal("not a tcp conn")
		}
		if err := tcp.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		if err := tcp.Close(); err != nil {
			t.Fatal(err)
		}
	}
	dropDeadline := time.Now().Add(2 * time.Second)
	for open.Load() > 0 && time.Now().Before(dropDeadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if open.Load() != 0 {
		t.Fatalf("stub still open %d", open.Load())
	}
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

type errReady string

func (e errReady) Error() string { return "ready line " + string(e) }
