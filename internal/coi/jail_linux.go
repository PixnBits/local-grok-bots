//go:build linux

package coi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const jailHomeInside = "/tmp/" + jailHomeName
const defaultSandboxBin = "bwrap"

func wrapCommand(spec jailSpec) (*exec.Cmd, error) {
	bwrap, err := sandboxBinary(spec.SandboxBin, "bwrap")
	if err != nil {
		return nil, err
	}
	args, err := linuxBwrapArgs(spec)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bwrap, args...)
	// Pid 1 inside --unshare-pid is this supervisor. Every process in the
	// jail can read its environment, so it gets a fixed PATH and nothing
	// from the daemon. The command is given spec.Env with --setenv after
	// --clearenv, which is also the forwarder's environment.
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	detach(cmd)
	return cmd, nil
}

func linuxBwrapArgs(spec jailSpec) ([]string, error) {
	bin, err := resolvedFile(spec.Bin)
	if err != nil {
		return nil, err
	}
	ws := filepath.Clean(spec.Workspace)
	if !filepath.IsAbs(ws) {
		return nil, ErrSandboxUnavailable
	}
	home := filepath.Clean(spec.Home)
	if !filepath.IsAbs(home) {
		return nil, ErrSandboxUnavailable
	}
	// Net is unshared, so the jail has no resolv.conf bind and no host /run.
	// The host proxy resolves allowlisted API hosts. IPC is a fresh namespace.
	args := []string{
		"--unshare-user", "--unshare-pid", "--unshare-uts",
		"--unshare-ipc", "--unshare-net",
		"--die-with-parent", "--new-session", "--clearenv",
	}
	for _, dir := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc"} {
		args = roBindTry(args, dir)
	}
	entry, entryArgs, extras := jailEntry(spec, jailProxySock)
	entryBin := bin
	if entry != spec.Bin {
		entryBin, err = resolvedFile(entry)
		if err != nil {
			return nil, err
		}
	}
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", home, jailHomeInside,
		"--bind", ws, ws,
		"--ro-bind", entryBin, entryBin,
		"--chdir", ws,
	)
	mounts, err := spoolMounts(ws, spec.Spool, spec.SpoolDev, spec.SpoolIno)
	if err != nil {
		return nil, err
	}
	for _, m := range mounts {
		args = append(args, "--tmpfs", m)
	}
	if orig := filepath.Clean(entry); orig != entryBin {
		args = append(args, "--ro-bind", entryBin, orig)
	}
	for _, extra := range extras {
		resolved, err := resolvedFile(extra)
		if err != nil {
			return nil, err
		}
		if resolved != entryBin {
			args = append(args, "--ro-bind", resolved, resolved)
		}
		if clean := filepath.Clean(extra); clean != resolved {
			args = append(args, "--ro-bind", resolved, clean)
		}
	}
	if spec.ProxySock != "" {
		args = append(args, "--bind", spec.ProxySock, jailProxySock)
	}
	for _, e := range spec.Env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		switch k {
		case "HOME":
			v = jailHomeInside
		case "GROK_HOME":
			v = jailHomeInside + "/.grok"
		case "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME":
			v = jailHomeInside
		case "TMPDIR":
			v = "/tmp"
		}
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--setenv", "PWD", ws)
	args = append(args, "--", entryBin)
	args = append(args, entryArgs...)
	return args, nil
}

func roBindTry(args []string, dir string) []string {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return args
	}
	return append(args, "--ro-bind", dir, dir)
}
