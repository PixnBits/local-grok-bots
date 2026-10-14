//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sandboxExec is fixed so a PATH entry cannot replace it.
const sandboxExec = "/usr/bin/sandbox-exec"

// HandleArgs has no re-exec stage on macOS; sandbox-exec applies the profile.
func HandleArgs(args []string) bool { return false }

// launch runs the command under sandbox-exec with a generated Seatbelt
// profile. There is no mount namespace, so the shell sees real paths and
// starts in the workspace instead of /work. The LD_PRELOAD proxy does not
// work on macOS, so net and ssh grants are denied and the network stays
// closed. A missing sandbox-exec fails closed.
func launch(ctx context.Context, p *prepared) (string, string, error) {
	if _, err := os.Stat(sandboxExec); err != nil {
		return "", "", fmt.Errorf("shell sandbox unavailable: %w", err)
	}
	ws, err := filepath.EvalSymlinks(p.workspace)
	if err != nil {
		return "", "", err
	}
	tmp := filepath.Join(p.dir, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", "", err
	}
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil {
		return "", "", err
	}
	var ro []string
	for _, m := range p.mounts {
		// Only build binds keep their host path; the /lgb wrappers need mounts.
		if !m.RO || m.Src != m.Dst || strings.HasPrefix(m.Dst, "/lgb") {
			continue
		}
		if real, err := filepath.EvalSymlinks(m.Src); err == nil {
			ro = append(ro, real)
		}
	}
	for _, g := range []string{"net", "ssh"} {
		if p.grants[g] {
			p.extra = append(p.extra, Event{Kind: "grant_denied", Grant: g, Detail: "network unavailable in the macOS sandbox"})
		}
	}
	prof, err := seatbeltProfile(seatbeltSpec{Workspace: ws, Tmp: tmp, ReadOnly: ro})
	if err != nil {
		return "", "", err
	}
	cmd := exec.Command(sandboxExec, "-p", prof, "/bin/sh", "-c", p.command)
	cmd.Dir = ws
	cmd.Env = []string{
		"PATH=" + darwinPATH(),
		"HOME=" + ws,
		"TMPDIR=" + tmp,
		"PWD=" + ws,
		"LANG=en_US.UTF-8",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
	}
	return capture(ctx, cmd)
}

func darwinPATH() string {
	var dirs []string
	for _, d := range []string{"/opt/homebrew/bin", "/usr/local/go/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return strings.Join(dirs, ":")
}
