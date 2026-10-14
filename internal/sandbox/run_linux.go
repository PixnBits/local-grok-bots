//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func launch(ctx context.Context, p *prepared) (string, string, error) {
	if path, err := exec.LookPath("bwrap"); err == nil {
		return runBwrap(ctx, p, path)
	}
	return runUnshare(ctx, p)
}

func runBwrap(ctx context.Context, p *prepared, bwrap string) (string, string, error) {
	args := []string{
		"--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-uts",
		"--die-with-parent", "--disable-userns", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/bin", "/bin",
		"--ro-bind", "/lib", "/lib",
	}
	if st, err := os.Stat("/lib64"); err == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}
	args = append(args,
		"--dir", "/etc",
		"--tmpfs", "/tmp",
		"--proc", "/proc",
		"--dev", "/dev",
		"--bind", p.workspace, "/work",
		"--chdir", "/work",
	)
	if st, err := os.Stat("/etc/ld.so.cache"); err == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache")
	}
	if st, err := os.Stat("/etc/ssl"); err == nil && st.IsDir() {
		args = append(args, "--ro-bind", "/etc/ssl", "/etc/ssl")
	}
	if st, err := os.Stat("/etc/services"); err == nil && !st.IsDir() {
		args = append(args, "--ro-bind", "/etc/services", "/etc/services")
	}
	for _, m := range p.mounts {
		flag := "--bind"
		if m.RO {
			flag = "--ro-bind"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	for _, e := range p.env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		args = append(args, "--setenv", k, v)
	}
	args = append(args, "--", "/bin/sh", "-c", p.command)
	cmd := exec.Command(bwrap, args...)
	return capture(ctx, cmd)
}

func runUnshare(ctx context.Context, p *prepared) (string, string, error) {
	if _, err := exec.LookPath("unshare"); err != nil {
		return "", "", fmt.Errorf("shell sandbox unavailable: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	jail, err := os.MkdirTemp("", "lgb-jail-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(jail)
	cfg := stage2File{Workspace: p.workspace, Command: p.command, Env: p.env, Mounts: p.mounts}
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", "", err
	}
	cfgPath := filepath.Join(p.dir, "stage2.json")
	if err := os.WriteFile(cfgPath, b, 0o644); err != nil {
		return "", "", err
	}
	cmd := exec.Command("/usr/bin/unshare",
		"--user", "--mount", "--net", "--map-root-user", "--propagation", "private",
		exe, "--sandbox-stage2", jail, cfgPath)
	return capture(ctx, cmd)
}

func stage2FromFile(jail, configPath string) error {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg stage2File
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	return enterJail(jail, cfg)
}
