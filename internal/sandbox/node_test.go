package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJailNodeUnsetShim(t *testing.T) {
	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{Workspace: ws, Command: "node"}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if !strings.HasPrefix(jailPATH(), JailNodeDir+":") {
		t.Fatalf("PATH %s", jailPATH())
	}
	if !strings.Contains(strings.Join(p.env, "\n"), "PATH="+jailPATH()) {
		t.Fatal("jail env PATH")
	}
	src := mountSrcRO(t, p.mounts, JailNodeDir)
	body, err := os.ReadFile(filepath.Join(src, "node"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), nodeUnsetText) {
		t.Fatalf("shim %s", body)
	}
	res, err := Run(ctx, Request{Workspace: ws, Command: "node"})
	if err == nil {
		t.Fatal("node exited 0")
	}
	if !strings.Contains(res.Stdout+res.Stderr, nodeUnsetText) {
		t.Fatalf("output %q %q err %v", res.Stdout, res.Stderr, err)
	}
}

func TestJailNodeMountsResolvedFile(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "real-node")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nprintf '%s\\n' from-node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outside, "node")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{Workspace: ws, Command: "node", NodePath: link}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	src := mountSrcRO(t, p.mounts, JailNodeDir)
	got, err := os.ReadFile(filepath.Join(src, "node"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "from-node") {
		t.Fatalf("mounted %s", got)
	}
	res, err := Run(ctx, Request{Workspace: ws, Command: "node", NodePath: link})
	if err != nil {
		t.Fatalf("run: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	if strings.TrimSpace(res.Stdout) != "from-node" {
		t.Fatalf("stdout %q stderr %q", res.Stdout, res.Stderr)
	}
}

func TestJailNodeRejectsInvalid(t *testing.T) {
	ws := t.TempDir()
	inside := filepath.Join(ws, "node")
	if err := os.WriteFile(inside, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, path := range []string{"", inside, filepath.Join(ws, "missing"), ws} {
		if path == "" {
			continue
		}
		_, err := prepare(ctx, Request{Workspace: ws, Command: "node", NodePath: path}, ws)
		if err == nil || !strings.Contains(err.Error(), "node") {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func TestJailNodeGoTestWeb(t *testing.T) {
	node := os.Getenv("LGB_JAIL_NODE")
	if node == "" {
		t.Skip("set LGB_JAIL_NODE to run go test ./web inside the jail")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	res, err := Run(ctx, Request{
		Workspace: root,
		Command:   "go test -count=1 -mod=readonly ./web",
		NodePath:  node,
		GoProxy:   "off",
		GoFlags:   "-mod=readonly",
	})
	out := res.Stdout + res.Stderr
	if err != nil {
		t.Fatalf("go test ./web: %v\n%s", err, out)
	}
	t.Log(out)
	if !strings.Contains(out, "ok") && !strings.Contains(out, "PASS") {
		t.Fatalf("output %s", out)
	}
}

func mountSrcRO(t *testing.T, mounts []mount, dst string) string {
	t.Helper()
	for _, m := range mounts {
		if m.Dst == dst && m.RO {
			return m.Src
		}
	}
	t.Fatalf("no read-only mount for %s", dst)
	return ""
}
