package sandbox

import (
	"context"
	"os"
	"os/exec"
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
	for _, needle := range []string{"GOPROXY=off", "GOTOOLCHAIN=local", "GOSUMDB=off", "GOFLAGS=", "GOENV=off", "GOWORK=off"} {
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
		if ev.Notice != "Go build cache is ephemeral for this command" || !strings.Contains(ev.Detail, "cache=ephemeral") || !strings.Contains(ev.Detail, "GOPROXY=off") || !strings.Contains(ev.Detail, "GOSUMDB=off") || !strings.Contains(ev.Detail, "GOTOOLCHAIN=local") {
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
	if !envHas(p.env, "GOPROXY=https://a.example") || !envHas(p.env, "GOFLAGS=-mod=readonly") || !envHas(p.env, "GOENV=off") || !envHas(p.env, "GOWORK=off") {
		t.Fatal(strings.Join(p.env, "\n"))
	}
	for _, ev := range p.extra {
		if ev.Kind == "jail_go_env" && (ev.Notice != "" || strings.Contains(ev.Detail, "cache=ephemeral")) {
			t.Fatalf("persistent cache %+v", ev)
		}
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
	if !goEnvEphemeral(p3.extra) {
		t.Fatal("symlink root did not record an ephemeral cache")
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

func TestJailGoEnvFileDoesNotStick(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatal("go is not installed")
	}
	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{
		Workspace:   ws,
		Command:     "true",
		GoProxy:     "https://a.example",
		GoToolchain: "local",
	}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	wrapSrc := ""
	for _, m := range p.mounts {
		if m.Dst == "/lgb/bin/go" {
			continue
		}
		b, err := os.ReadFile(m.Src)
		if err != nil {
			continue
		}
		text := string(b)
		if strings.HasPrefix(text, "#!/bin/sh") && strings.Contains(text, "GOENV=off") && strings.Contains(text, "/lgb/bin/go") {
			wrapSrc = text
			break
		}
	}
	if wrapSrc == "" {
		t.Fatal("go wrapper was not installed")
	}
	real, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	real, err = filepath.Abs(real)
	if err != nil {
		t.Fatal(err)
	}
	wrapSrc = strings.ReplaceAll(wrapSrc, "/lgb/bin/go", real)
	wrap := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(wrap, []byte(wrapSrc), 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	envFile := filepath.Join(home, ".config", "go", "env")
	if err := os.MkdirAll(filepath.Dir(envFile), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "GOPROXY=https://evil.example\nGOTOOLCHAIN=go1.99.0\nGOFLAGS=-mod=mod\nGOSUMDB=sum.golang.org\n"
	if err := os.WriteFile(envFile, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(ctx, wrap, args...)
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + home,
			"GOENV=" + envFile,
			"GOPROXY=https://prefix.example",
			"GOTOOLCHAIN=auto",
			"GOFLAGS=-mod=mod",
			"GOSUMDB=sum.golang.org",
			"GOWORK=on",
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	want := "https://a.example\nlocal\n\noff"
	out, err := run("env", "GOPROXY", "GOTOOLCHAIN", "GOFLAGS", "GOSUMDB")
	if err != nil {
		t.Fatalf("go env: %v\n%s", err, out)
	}
	if strings.TrimRight(out, "\n") != want {
		t.Fatalf("effective env:\n%q", out)
	}
	if _, err := run("env", "-w", "GOPROXY=https://evil.example", "GOTOOLCHAIN=go1.99.0", "GOFLAGS=-mod=mod", "GOSUMDB=sum.golang.org"); err != nil {
		t.Logf("go env -w: %v", err)
	}
	out, err = run("env", "GOPROXY", "GOTOOLCHAIN", "GOFLAGS", "GOSUMDB")
	if err != nil {
		t.Fatalf("go env after -w: %v\n%s", err, out)
	}
	if strings.TrimRight(out, "\n") != want {
		t.Fatalf("env file stuck:\n%q", out)
	}
}

func TestJailGoCacheSymlinkAncestor(t *testing.T) {
	ws := t.TempDir()
	realParent := t.TempDir()
	data := filepath.Join(realParent, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := t.TempDir()
	home := filepath.Join(linkParent, "home")
	if err := os.Symlink(realParent, home); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(home, "data", "bots", "bot1")
	resolvedData, err := filepath.EvalSymlinks(filepath.Join(home, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if resolvedData == filepath.Join(home, "data") {
		t.Fatal("ancestor symlink was not visible")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := prepare(ctx, Request{Workspace: ws, Command: "true", BotGoRoot: via}, ws)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if _, err := os.Lstat(filepath.Join(resolvedData, "bots", "bot1", "go", "mod")); err == nil {
		t.Fatal("unresolved root wrote a cache")
	}
	if !goEnvEphemeral(p.extra) {
		t.Fatal("unresolved root did not record an ephemeral cache")
	}

	root := filepath.Join(resolvedData, "bots", "bot1")
	p2, err := prepare(ctx, Request{Workspace: ws, Command: "true", BotGoRoot: root}, ws)
	if err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(root, "go", "mod")
	marker := filepath.Join(mod, "pin.txt")
	if err := os.WriteFile(marker, []byte("pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	if goEnvEphemeral(p2.extra) {
		t.Fatal("resolved root used an ephemeral cache")
	}
	p2.close()
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("cache did not survive the command: %v", err)
	}
}

func goEnvEphemeral(extra []Event) bool {
	for _, ev := range extra {
		if ev.Kind == "jail_go_env" && ev.Notice == "Go build cache is ephemeral for this command" && strings.Contains(ev.Detail, "cache=ephemeral") {
			return true
		}
	}
	return false
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
