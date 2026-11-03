//go:build linux

package sandbox

import (
	"context"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitLsRemoteDoesNotHoldStderr(t *testing.T) {
	for _, bin := range []string{"bwrap", "git", "gcc"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is required")
		}
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "github.sock")
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
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	res, err := Run(ctx, Request{
		Workspace:   t.TempDir(),
		Command:     "git ls-remote https://github.com/acme/widgets 2>&1 | tail -n 3; echo END",
		Grants:      []string{"git", "github"},
		GitHubSock:  sock,
		GitHubRepos: []string{"acme/widgets"},
	})
	elapsed := time.Since(start)
	out := res.Stdout + res.Stderr
	if !strings.Contains(out, "END") {
		t.Fatalf("err=%v elapsed=%s\n%s", err, elapsed, out)
	}
	if elapsed >= 10*time.Second {
		t.Fatalf("elapsed %s\n%s", elapsed, out)
	}
}
