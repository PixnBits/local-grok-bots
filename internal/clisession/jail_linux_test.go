//go:build linux

package clisession

import (
	"context"
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
		"printf '%s\\n' '{\"type\":\"result\",\"result\":\"ok\",\"session_id\":\"s\"}'\n"
	if err := os.WriteFile(probe, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := (ExecRunner{HasTTY: func() bool { return false }}).Run(ctx, Spec{
		Backend: "grok", Bin: probe, Prompt: "hi", Workspace: ws,
		PermissionMode: "always-allow",
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

func TestGrokBwrapArgsShareNetAndSkipSandbox(t *testing.T) {
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
		Isolate:   &Isolation{Home: home, Env: []string{"HOME=" + home, "PATH=/usr/bin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	if !strings.Contains(joined, "--unshare-pid") || !strings.Contains(joined, "--proc\n/proc") {
		t.Fatalf("pid ns %v", args)
	}
	if strings.Contains(joined, "--unshare-net") {
		t.Fatal("unshared net")
	}
	if strings.Contains(joined, "--sandbox") {
		t.Fatal("nested sandbox flag")
	}
	if !strings.Contains(joined, "--bind\n"+ws+"\n"+ws) {
		t.Fatalf("workspace bind %v", args)
	}
}
