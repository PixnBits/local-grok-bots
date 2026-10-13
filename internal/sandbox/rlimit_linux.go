//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// BwrapCommand runs bwrap with args. When args name a resource limit and this
// bubblewrap has no --rlimit flag, a short re-exec applies setrlimit and then
// execs bwrap without that flag. Zero limits exec bwrap directly.
func BwrapCommand(bwrap string, args []string) (*exec.Cmd, error) {
	rest, limits, err := SplitBwrapRlimits(args)
	if err != nil {
		return nil, err
	}
	if limits.Zero() || bwrapHasRlimit(bwrap) {
		return exec.Command(bwrap, args...), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	prefix := []string{
		"--sandbox-rlimit",
		strconv.Itoa(limits.Nofile),
		strconv.Itoa(limits.Nproc),
		strconv.Itoa(limits.CPUSeconds),
		"--",
		bwrap,
	}
	return exec.Command(exe, append(prefix, rest...)...), nil
}

func bwrapHasRlimit(path string) bool {
	rlimitHelpOnce.Do(func() {
		cmd := exec.Command(path, "--help")
		out, _ := cmd.CombinedOutput()
		rlimitHelp = strings.Contains(string(out), "--rlimit")
	})
	return rlimitHelp
}

var (
	rlimitHelpOnce sync.Once
	rlimitHelp     bool
)

func applyRlimits(r Rlimits) error {
	if r.Nofile > 0 {
		if err := setRlimit(unix.RLIMIT_NOFILE, r.Nofile); err != nil {
			return fmt.Errorf("rlimit nofile: %w", err)
		}
	}
	if r.Nproc > 0 {
		if err := setRlimit(unix.RLIMIT_NPROC, r.Nproc); err != nil {
			return fmt.Errorf("rlimit nproc: %w", err)
		}
	}
	if r.CPUSeconds > 0 {
		if err := setRlimit(unix.RLIMIT_CPU, r.CPUSeconds); err != nil {
			return fmt.Errorf("rlimit cpu: %w", err)
		}
	}
	return nil
}

func setRlimit(res int, n int) error {
	lim := unix.Rlimit{Cur: uint64(n), Max: uint64(n)}
	return unix.Setrlimit(res, &lim)
}

func rlimitAndExec(args []string) error {
	if len(args) < 5 || args[3] != "--" {
		return fmt.Errorf("rlimit exec: bad arguments")
	}
	var r Rlimits
	var err error
	if r.Nofile, err = strconv.Atoi(args[0]); err != nil {
		return fmt.Errorf("rlimit exec: %w", err)
	}
	if r.Nproc, err = strconv.Atoi(args[1]); err != nil {
		return fmt.Errorf("rlimit exec: %w", err)
	}
	if r.CPUSeconds, err = strconv.Atoi(args[2]); err != nil {
		return fmt.Errorf("rlimit exec: %w", err)
	}
	if err := applyRlimits(r); err != nil {
		return err
	}
	argv := args[4:]
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("rlimit exec: missing command")
	}
	return unix.Exec(argv[0], argv, os.Environ())
}
