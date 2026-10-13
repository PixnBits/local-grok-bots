//go:build linux

package sandbox

import (
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
