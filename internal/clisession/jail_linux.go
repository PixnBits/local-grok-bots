//go:build linux

package clisession

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func grokHostJail() bool { return true }

func wrapGrokJail(ctx context.Context, bin string, args []string, spec Spec) (*exec.Cmd, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, &SandboxError{Backend: "grok", Err: fmt.Errorf("Grok's process jail needs bwrap (%v), so the turn was refused", err)}
	}
	bargs, err := grokBwrapArgs(bin, args, spec)
	if err != nil {
		return nil, &SandboxError{Backend: "grok", Err: err}
	}
	cmd := exec.CommandContext(ctx, bwrap, bargs...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd, nil
}

func grokBwrapArgs(bin string, args []string, spec Spec) ([]string, error) {
	ws, err := absClean(spec.Workspace)
	if err != nil || !filepath.IsAbs(ws) {
		return nil, fmt.Errorf("workspace is not available")
	}
	st, err := os.Stat(ws)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("workspace is not available")
	}
	resolved, err := resolveFile(bin)
	if err != nil {
		return nil, fmt.Errorf("cli binary is not available")
	}
	args = stripSandboxFlag(args)
	// Nested Grok bwrap cannot create a user namespace when unprivileged
	// user namespaces are restricted. This jail is the pid boundary.
	// Network is shared so the loopback credential proxy stays reachable.
	out := []string{
		"--unshare-user", "--unshare-pid", "--unshare-uts", "--unshare-ipc",
		"--die-with-parent", "--clearenv",
	}
	for _, dir := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc"} {
		out = roBindDir(out, dir)
	}
	out = append(out,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--bind", ws, ws,
		"--ro-bind", resolved, resolved,
		"--chdir", ws,
	)
	if clean := filepath.Clean(bin); clean != resolved {
		out = append(out, "--ro-bind", resolved, clean)
	}
	seen := map[string]bool{ws: true}
	env := []string{}
	if spec.Isolate != nil {
		env = spec.Isolate.Env
	}
	for _, dir := range []string{envVal(env, "HOME"), envVal(env, "GROK_HOME"), spec.IsolateHome()} {
		dir = filepath.Clean(strings.TrimSpace(dir))
		if dir == "" || dir == "." || !filepath.IsAbs(dir) || seen[dir] {
			continue
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		if isWithin(ws, dir) {
			continue
		}
		out = append(out, "--bind", dir, dir)
		seen[dir] = true
	}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !hostJailLogKey(k) {
			continue
		}
		v = filepath.Clean(v)
		if !filepath.IsAbs(v) || seen[v] {
			continue
		}
		if st, err := os.Stat(v); err != nil {
			if err := os.WriteFile(v, nil, 0o600); err != nil {
				continue
			}
		} else if st.IsDir() {
			continue
		}
		out = append(out, "--bind", v, v)
		seen[v] = true
	}
	out = append(out, "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PWD", ws, "--setenv", "TMPDIR", "/tmp")
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			continue
		}
		if k == "TMPDIR" {
			v = "/tmp"
		}
		out = append(out, "--setenv", k, v)
	}
	out = append(out, "--", resolved)
	out = append(out, args...)
	return out, nil
}

func (s Spec) IsolateHome() string {
	if s.Isolate == nil {
		return ""
	}
	return s.Isolate.Home
}

func stripSandboxFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--sandbox" {
			if i+1 < len(args) {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "--sandbox=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func hostJailLogKey(k string) bool {
	switch k {
	case "LGB_ENV_LOG", "LGB_ARGV_LOG", "LGB_FIXTURE", "LGB_AUTH_LOG":
		return true
	}
	return false
}

func envVal(env []string, key string) string {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return env[i][len(prefix):]
		}
	}
	return ""
}

func roBindDir(args []string, dir string) []string {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return args
	}
	return append(args, "--ro-bind", dir, dir)
}

func resolveFile(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("cli binary is not available")
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(resolved)
	if err != nil || st.IsDir() {
		return "", fmt.Errorf("cli binary is not available")
	}
	return resolved, nil
}
