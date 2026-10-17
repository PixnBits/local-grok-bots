//go:build linux

package clisession

import (
	"context"
	"errors"
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
		var bridge *BridgeError
		if errors.As(err, &bridge) {
			return nil, err
		}
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
	// The network namespace is empty. Host sockets are bind-mounted and an
	// in-jail forwarder publishes them on 127.0.0.1.
	out := []string{
		"--unshare-user", "--unshare-pid", "--unshare-uts", "--unshare-ipc",
		"--unshare-net", "--die-with-parent", "--new-session", "--clearenv",
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
	// Read-only overlays sit on top of the writable home bind. A later
	// mount must not cover them.
	sealed, err := grokSealBinds(envVal(env, "GROK_HOME"))
	if err != nil {
		return nil, err
	}
	out = append(out, sealed...)
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
		if !ok || k == "" || dropJailProxyEnv(k) {
			continue
		}
		if k == "TMPDIR" {
			v = "/tmp"
		}
		out = append(out, "--setenv", k, v)
	}
	entry := resolved
	entryArgs := append([]string{}, args...)
	if spec.Isolate != nil && strings.TrimSpace(spec.Isolate.ForwardBin) != "" {
		fwd, ferr := resolvePlainFile(spec.Isolate.ForwardBin)
		if ferr != nil || len(spec.Isolate.ForwardArgs) == 0 {
			return nil, &BridgeError{Err: fmt.Errorf("credential bridge is not available")}
		}
		if err := appendExtraBinds(&out, spec.Isolate.ExtraBinds); err != nil {
			return nil, &BridgeError{Err: err}
		}
		if fwd != resolved {
			out = append(out, "--ro-bind", fwd, fwd)
		}
		entry = fwd
		entryArgs = append(append([]string{}, spec.Isolate.ForwardArgs...), "--", resolved)
		entryArgs = append(entryArgs, args...)
	}
	out = append(out, "--", entry)
	out = append(out, entryArgs...)
	return out, nil
}

func dropJailProxyEnv(k string) bool {
	switch strings.ToUpper(k) {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY":
		return true
	default:
		return false
	}
}

func resolvePlainFile(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("bridge binary is not available")
	}
	st, err := os.Lstat(clean)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return "", fmt.Errorf("bridge binary is not available")
	}
	return clean, nil
}

func appendExtraBinds(out *[]string, binds [][2]string) error {
	if len(binds) == 0 {
		return fmt.Errorf("bridge socket is not available")
	}
	seen := map[string]bool{}
	for _, pair := range binds {
		host, jail := pair[0], pair[1]
		if (jail != JailProxySock && jail != JailEgressSock) || seen[jail] || !filepath.IsAbs(host) {
			return fmt.Errorf("bridge socket is not available")
		}
		seen[jail] = true
		st, err := os.Lstat(host)
		if err != nil || st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bridge socket is not available")
		}
		if !st.Mode().IsRegular() && st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("bridge socket is not available")
		}
		*out = append(*out, "--bind", host, jail)
	}
	return nil
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
