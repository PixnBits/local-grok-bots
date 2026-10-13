//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellRlimitArgv(t *testing.T) {
	plain := shellBwrapArgs(&prepared{workspace: "/tmp/ws", command: "true"})
	if strings.Contains(strings.Join(plain, "\x00"), "--rlimit") {
		t.Fatal("zero rlimits changed the argv")
	}
	args := shellBwrapArgs(&prepared{
		workspace: "/tmp/ws",
		command:   "true",
		rlimits:   Rlimits{Nofile: 1024, Nproc: 64, CPUSeconds: 15},
	})
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--rlimit\x00NOFILE\x001024\x001024",
		"--rlimit\x00NPROC\x0064\x0064",
		"--rlimit\x00CPU\x0015\x0015",
		"--bind\x00/tmp/ws\x00/work",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, strings.Join(args, " "))
		}
	}
}

func TestShellWorkspaceReadonly(t *testing.T) {
	ws := t.TempDir()
	args := shellBwrapArgs(&prepared{workspace: ws, command: "true", readonly: true})
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--ro-bind\x00"+ws+"\x00/work") || strings.Contains(joined, "--bind\x00"+ws+"\x00") {
		t.Fatalf("workspace mount:\n%s", strings.Join(args, " "))
	}
	res, err := runCmd(t, Request{Workspace: ws, Command: "touch ro-proof", WorkspaceReadonly: true})
	if err == nil {
		t.Fatalf("write succeeded: %s %s", res.Stdout, res.Stderr)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "ro-proof")); !os.IsNotExist(statErr) {
		t.Fatalf("read-only workspace created ro-proof (%v)", statErr)
	}
	ev, ok := findEvent(res.Events, "sandbox_block", "", "")
	if !ok || ev.Detail != "workspace is read-only" {
		t.Fatalf("%+v stderr=%s", res.Events, res.Stderr)
	}
}

func TestShellRlimitNofile(t *testing.T) {
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   "ulimit -n",
		Rlimits:   Rlimits{Nofile: 1024},
	})
	if err != nil || strings.TrimSpace(res.Stdout) != "1024" {
		t.Fatalf("nofile %v stdout=%q stderr=%q", err, res.Stdout, res.Stderr)
	}
}
