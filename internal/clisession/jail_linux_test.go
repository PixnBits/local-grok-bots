//go:build linux

package clisession

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStripSandboxFlag(t *testing.T) {
	got := stripSandboxFlag([]string{"-p", "hi", "--sandbox", "lgb", "--cwd", "/w", "--sandbox=off"})
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "sandbox") || strings.Contains(joined, "lgb") || strings.Contains(joined, "off") {
		t.Fatalf("args %v", got)
	}
	if joined != "-p hi --cwd /w" {
		t.Fatalf("args %v", got)
	}
}

func TestGrokJailHidesHostProc(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	host := exec.Command("/usr/bin/sleep", "30")
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if host.Process != nil {
			_ = host.Process.Kill()
			_, _ = host.Process.Wait()
		}
	})
	ws := t.TempDir()
	home := t.TempDir()
	out := filepath.Join(ws, "probe.out")
	probe := filepath.Join(ws, "probe.sh")
	body := "#!/bin/sh\n" +
		"{\n" +
		"  if [ -e \"/proc/$HOST_PROBE_PID\" ]; then echo HOST_PID=visible; else echo HOST_PID=hidden; fi\n" +
		"  if [ -e \"/proc/$HOST_PROBE_PID/environ\" ]; then echo HOST_ENV=visible; else echo HOST_ENV=hidden; fi\n" +
		"  if [ -e \"/proc/$HOST_PROBE_PID/fd\" ]; then echo HOST_FD=visible; else echo HOST_FD=hidden; fi\n" +
		"  echo COMM1=$(cat /proc/1/comm 2>/dev/null | tr -d '\\n')\n" +
		"} > \"$HOST_PROBE_OUT\"\n" +
		acpShellTail()
	if err := os.WriteFile(probe, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: probe, Prompt: "hi", Workspace: ws,
		PermissionMode: "always-allow",
		ACP:            quietACP(),
		Isolate: &Isolation{
			Home:        home,
			GrokSandbox: GrokProfile,
			Env: []string{
				"PATH=/usr/bin:/bin",
				"HOME=" + home,
				"HOST_PROBE_PID=" + strconv.Itoa(host.Process.Pid),
				"HOST_PROBE_OUT=" + out,
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("run: %v res %+v", err, res)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"HOST_PID=hidden", "HOST_ENV=hidden", "HOST_FD=hidden", "COMM1=bwrap"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s:\n%s", want, text)
		}
	}
}

func TestGrokBwrapArgsUnshareNetAndSkipSandbox(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	ws := t.TempDir()
	home := t.TempDir()
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := grokBwrapArgs(bin, []string{"-p", "hi", "--sandbox", "lgb", "--cwd", ws}, Spec{
		Workspace: ws,
		Isolate: &Isolation{Home: home, Env: []string{
			"HOME=" + home, "PATH=/usr/bin", "HTTP_PROXY=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--unshare-pid") || !strings.Contains(joined, "--proc\n/proc") {
		t.Fatalf("pid ns %v", args)
	}
	if !strings.Contains(joined, "--unshare-net") || !strings.Contains(joined, "--new-session") {
		t.Fatal("missing net or session isolation")
	}
	if strings.Contains(joined, "--sandbox") || strings.Contains(joined, "HTTP_PROXY") || strings.Contains(joined, "https_proxy") {
		t.Fatalf("sandbox flag or host proxy env leaked:\n%s", joined)
	}
	if !strings.Contains(joined, "--bind\n"+ws+"\n"+ws) {
		t.Fatalf("workspace bind %v", args)
	}
}

func TestGrokBwrapForwarderBindsSockets(t *testing.T) {
	ws := t.TempDir()
	home := t.TempDir()
	bin := filepath.Join(ws, "grok")
	fwd := filepath.Join(t.TempDir(), "lgb")
	cred := filepath.Join(t.TempDir(), "sock")
	egress := filepath.Join(t.TempDir(), "sock")
	for _, p := range []string{bin, fwd, cred, egress} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args, err := grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate: &Isolation{
			Home:        home,
			Env:         []string{"HOME=" + home},
			ForwardBin:  fwd,
			ForwardArgs: []string{"--coi-forward", "--sock", JailProxySock, "--keep-key", "--http-sock", JailEgressSock},
			ExtraBinds:  [][2]string{{cred, JailProxySock}, {egress, JailEgressSock}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"--unshare-net", "--new-session", "--coi-forward", "--keep-key",
		"--bind\n" + cred + "\n" + JailProxySock,
		"--bind\n" + egress + "\n" + JailEgressSock,
		"--ro-bind\n" + fwd + "\n" + fwd,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "/run") {
		t.Fatalf("host run leaked\n%s", joined)
	}
}

func TestGrokBwrapDoesNotBindRuleFiles(t *testing.T) {
	ws := t.TempDir()
	state := t.TempDir()
	home := filepath.Join(state, "home")
	if err := os.MkdirAll(filepath.Join(home, ".grok"), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		p := filepath.Join(state, name)
		if err := os.WriteFile(p, []byte("rules\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	if err := SealGrokHome(state, filepath.Join(home, ".grok")); err != nil {
		t.Fatal(err)
	}
	args, err := grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate: &Isolation{Home: home, Env: []string{
			"HOME=" + home,
			"GROK_HOME=" + filepath.Join(home, ".grok"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--bind\n"+home+"\n"+home) {
		t.Fatalf("home not bound:\n%s", joined)
	}
	req := filepath.Join(home, ".grok", "requirements.toml")
	sealedHome := filepath.Join(home, ".grok")
	bindAt := strings.Index(joined, "--bind\n"+sealedHome+"\n"+sealedHome)
	roAt := strings.Index(joined, "--ro-bind\n"+req+"\n"+req)
	if bindAt < 0 || roAt < bindAt {
		t.Fatalf("sealed name is not read-only over the home bind:\n%s", joined)
	}
	for _, p := range files {
		if strings.Contains(joined, p) {
			t.Fatalf("rule file bound %s\n%s", p, joined)
		}
	}
	userHome := t.TempDir()
	grokHome := filepath.Join(state, "grok-home")
	if err := os.MkdirAll(grokHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SealGrokHome(state, grokHome); err != nil {
		t.Fatal(err)
	}
	args, err = grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate: &Isolation{Home: userHome, Env: []string{
			"HOME=" + userHome,
			"GROK_HOME=" + grokHome,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(args, "\n")
	if !strings.Contains(joined, "--bind\n"+grokHome+"\n"+grokHome) {
		t.Fatalf("grok home not bound:\n%s", joined)
	}
	for _, p := range files {
		if strings.Contains(joined, p) {
			t.Fatalf("rule file bound beside grok home %s\n%s", p, joined)
		}
	}
}

func TestGrokJailSealedNamesAreReadOnly(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip(err)
	}
	user := t.TempDir()
	state := t.TempDir()
	home := filepath.Join(state, "home")
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user,
	})
	if err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	out := filepath.Join(ws, "probe.out")
	bin := writeScript(t, ws, "probe.sh", `#!/bin/sh
gh="$GROK_HOME"
{
  if printf x >> "$gh/requirements.toml" 2>/dev/null; then echo REQ_WRITE=ok; else echo REQ_WRITE=blocked; fi
  if printf x >> "$gh/config.toml" 2>/dev/null; then echo CFG_WRITE=ok; else echo CFG_WRITE=blocked; fi
  if printf x >> "$gh/hooks/placeholder" 2>/dev/null; then echo HOOK_WRITE=ok; else echo HOOK_WRITE=blocked; fi
  if printf x > "$gh/hooks/extra" 2>/dev/null; then echo HOOK_NEW=ok; else echo HOOK_NEW=blocked; fi
  if mkdir -p "$gh/sessions" && printf n > "$gh/sessions/n"; then echo SESS=ok; else echo SESS=blocked; fi
} > "$PROBE_OUT"
`+acpShellTail())
	iso.Env = append(iso.Env, "PROBE_OUT="+out, "PATH=/usr/bin:/bin")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: bin, Fresh: true, Prompt: "hi", Workspace: ws,
		ACP: quietACP(), Isolate: &iso,
	}, nil)
	if err != nil {
		t.Fatalf("run: %v res %+v", err, res)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{"REQ_WRITE=blocked", "CFG_WRITE=blocked", "HOOK_WRITE=blocked", "HOOK_NEW=blocked", "SESS=ok"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s:\n%s", want, text)
		}
	}
	var gh string
	for _, e := range iso.Env {
		if strings.HasPrefix(e, "GROK_HOME=") {
			gh = strings.TrimPrefix(e, "GROK_HOME=")
		}
	}
	req, err := os.ReadFile(filepath.Join(gh, "requirements.toml"))
	if err != nil || string(req) != grokSealMarker {
		t.Fatalf("requirements %q %v", req, err)
	}
	cfg, err := os.ReadFile(filepath.Join(gh, "config.toml"))
	if err != nil || string(cfg) != grokPermissionTOML() {
		t.Fatalf("config changed: %v", err)
	}
	hook, err := os.ReadFile(filepath.Join(gh, "hooks", grokSealDirEntry))
	if err != nil || string(hook) != grokSealMarker {
		t.Fatalf("hook %q %v", hook, err)
	}
	if _, err := os.Lstat(filepath.Join(gh, "hooks", "extra")); !os.IsNotExist(err) {
		t.Fatalf("new hook file: %v", err)
	}
	sess, err := os.ReadFile(filepath.Join(gh, "sessions", "n"))
	if err != nil || string(sess) != "n" {
		t.Fatalf("session %q %v", sess, err)
	}
}

func TestGrokBwrapRejectsMissingBridge(t *testing.T) {
	ws := t.TempDir()
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := grokBwrapArgs(bin, []string{"-p", "hi"}, Spec{
		Workspace: ws,
		Isolate: &Isolation{
			ForwardBin:  filepath.Join(t.TempDir(), "missing"),
			ForwardArgs: []string{"--coi-forward"},
			ExtraBinds:  [][2]string{{filepath.Join(t.TempDir(), "sock"), JailProxySock}},
		},
	})
	var bridge *BridgeError
	if !errors.As(err, &bridge) {
		t.Fatalf("err %v", err)
	}
}
