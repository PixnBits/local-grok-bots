//go:build linux

package coi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const jailHomeInside = "/tmp/" + jailHomeName

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
	args := []string{
		"--unshare-user", "--unshare-pid", "--unshare-uts",
		"--die-with-parent", "--clearenv",
	}
	for _, dir := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc", "/run"} {
		args = roBindTry(args, dir)
	}
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", home, jailHomeInside,
		"--bind", ws, ws,
		"--ro-bind", bin, bin,
		"--chdir", ws,
	)
	if orig := filepath.Clean(spec.Bin); orig != bin {
		args = append(args, "--ro-bind", bin, orig)
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
	args = append(args, "--", bin)
	args = append(args, spec.Args...)
	return args, nil
}

func roBindTry(args []string, dir string) []string {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return args
	}
	return append(args, "--ro-bind", dir, dir)
}
