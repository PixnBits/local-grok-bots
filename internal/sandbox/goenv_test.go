package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJailGoEnvDefaults(t *testing.T) {
	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{Workspace: ws, Command: "true"}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	env := strings.Join(p.env, "\n")
	for _, needle := range []string{"GOPROXY=off", "GOTOOLCHAIN=local", "GOSUMDB=off", "GOFLAGS="} {
		if !envHas(p.env, needle) {
			t.Fatalf("missing %s in %s", needle, env)
		}
	}
	if line := envLine(p.env, "GOFLAGS"); line != "GOFLAGS=" {
		t.Fatalf("flags %q", line)
	}
	for _, host := range []string{"proxy.golang.org", "sum.golang.org", "storage.googleapis.com"} {
		if strings.Contains(env, host) {
			t.Fatalf("default env names %s", host)
		}
	}
	if runtime.GOOS == "linux" {
		if !envHas(p.env, "GOMODCACHE=/lgb/go/mod") || !envHas(p.env, "GOCACHE=/lgb/go/cache") {
			t.Fatal(env)
		}
	} else if !envHasPrefix(p.env, "GOMODCACHE=") || !envHasPrefix(p.env, "GOCACHE=") {
		t.Fatal(env)
	}
	saw := false
	for _, ev := range p.extra {
		if ev.Kind != "jail_go_env" {
			continue
		}
		saw = true
		if ev.Notice != "" || !strings.Contains(ev.Detail, "GOPROXY=off") || !strings.Contains(ev.Detail, "GOSUMDB=off") || !strings.Contains(ev.Detail, "GOTOOLCHAIN=local") {
			t.Fatalf("event %+v", ev)
		}
	}
	if !saw {
		t.Fatal("missing jail_go_env")
	}
}

func TestJailGoEnvCacheRoot(t *testing.T) {
	ws := t.TempDir()
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{Workspace: ws, Command: "true", BotGoRoot: root, GoProxy: "https://a.example", GoToolchain: "local", GoFlags: "-mod=readonly"}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	mod := filepath.Join(root, "go", "mod")
	cache := filepath.Join(root, "go", "cache")
	for _, dir := range []string{mod, cache} {
		st, err := os.Lstat(dir)
		if err != nil || !st.IsDir() {
			t.Fatalf("cache %s: %v", dir, err)
		}
	}
	if runtime.GOOS == "linux" {
		if !mountHas(p.mounts, mod, "/lgb/go/mod") || !mountHas(p.mounts, cache, "/lgb/go/cache") {
			t.Fatalf("mounts %+v", p.mounts)
		}
	}
	if !envHas(p.env, "GOPROXY=https://a.example") || !envHas(p.env, "GOFLAGS=-mod=readonly") {
		t.Fatal(strings.Join(p.env, "\n"))
	}

	inside := filepath.Join(ws, "go-cache")
	p2, err := prepare(ctx, Request{Workspace: ws, Command: "true", BotGoRoot: inside}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.close()
	if _, err := os.Lstat(filepath.Join(inside, "go", "mod")); err == nil {
		t.Fatal("cache created inside the workspace")
	}

	real := t.TempDir()
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "bots")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(link, "bot1")
	p3, err := prepare(ctx, Request{Workspace: ws, Command: "true", BotGoRoot: linked}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p3.close()
	if _, err := os.Lstat(filepath.Join(real, "bot1", "go", "mod")); err == nil {
		t.Fatal("cache followed a symlink")
	}

	p4, err := prepare(ctx, Request{Workspace: ws, Command: "true", GoProxy: "https://user:notsecret@proxy.example"}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p4.close()
	for _, ev := range p4.extra {
		if ev.Kind == "jail_go_env" && strings.Contains(ev.Detail, "notsecret") {
			t.Fatalf("event kept proxy userinfo %s", ev.Detail)
		}
	}
}

func envHas(env []string, needle string) bool {
	for _, line := range env {
		if line == needle {
			return true
		}
	}
	return false
}

func envHasPrefix(env []string, prefix string) bool {
	for _, line := range env {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func envLine(env []string, key string) string {
	prefix := key + "="
	for _, line := range env {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func mountHas(mounts []mount, src, dst string) bool {
	src = filepath.Clean(src)
	for _, m := range mounts {
		if filepath.Clean(m.Src) == src && m.Dst == dst && !m.RO {
			return true
		}
	}
	return false
}
