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

func TestJailNodeCheckOutsideWorkspace(t *testing.T) {
	base := canonicalTemp(t)
	ws := filepath.Join(base, "ws")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	good := writeNodeFile(t, outside, 0o755)
	got, err := checkJailNode(good, ws)
	if err != nil || got != good {
		t.Fatalf("outside node %q err %v", got, err)
	}

	inside := writeNodeFile(t, ws, 0o755)
	if _, err := checkJailNode(inside, ws); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("inside: %v", err)
	}

	link := filepath.Join(outside, "via-link")
	if err := os.Symlink(inside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := checkJailNode(link, ws); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("symlink into workspace: %v", err)
	}

	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	realNode := writeNodeFile(t, real, 0o755)
	wsLink := filepath.Join(base, "ws-link")
	if err := os.Symlink(real, wsLink); err != nil {
		t.Fatal(err)
	}
	// The node path is not under the workspace string. The workspace string
	// resolves to the directory that holds the node, so the second comparison
	// is the one that rejects it.
	if _, err := checkJailNode(realNode, wsLink); err == nil || !strings.Contains(err.Error(), "outside the workspace") {
		t.Fatalf("symlinked workspace: %v", err)
	}

	dirNode := filepath.Join(outside, "dir-node")
	if err := os.Mkdir(dirNode, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := checkJailNode(dirNode, ws); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Fatalf("directory: %v", err)
	}

	plain := writeNodeFile(t, outside, 0o644)
	if _, err := checkJailNode(plain, ws); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("non-exec: %v", err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, good)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(rel) {
		t.Fatalf("relative path is absolute: %s", rel)
	}
	if _, err := checkJailNode(rel, ws); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative %s: %v", rel, err)
	}
}

func canonicalTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if real != filepath.Clean(dir) {
		t.Fatalf("temp %s resolves to %s", dir, real)
	}
	return dir
}

func writeNodeFile(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "node-"+mode.String())
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' node-ok\n"), mode); err != nil {
		t.Fatal(err)
	}
	return path
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
