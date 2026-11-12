package permbroker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// describeStyle is a name shaped like a git describe result
// (`<name>-<n>-g<hex>`). Those ask before any repository check.
var describeStyleRe = regexp.MustCompile(`(?i).*-[0-9]+-g[0-9a-f]{7,40}$`)

func describeStyle(p string) bool {
	return describeStyleRe.MatchString(p)
}

// showObjectOK is true when show may auto-approve this object.
// HEAD-relative forms are commits and do not run git. Other names run a
// read-only type check in the workspace repository and allow only a commit.
// A missing repository, a timeout, or any other result asks.
func showObjectOK(ws, name string) bool {
	if describeStyle(name) {
		return false
	}
	if !plainCommitish(name) {
		return false
	}
	if headish(name) {
		return true
	}
	return gitCommitObject(ws, name)
}

func gitCommitObject(ws, name string) bool {
	ws = strings.TrimSpace(ws)
	if ws == "" || !filepath.IsAbs(ws) || strings.ContainsRune(name, 0) {
		return false
	}
	gitDir := filepath.Join(ws, ".git")
	st, err := os.Lstat(gitDir)
	if err != nil || !st.IsDir() {
		return false
	}
	if !lexicalInside(gitDir, ws) && filepath.Clean(gitDir) != filepath.Clean(ws) {
		return false
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		return false
	}
	hooks, err := os.MkdirTemp("", "lgb-git-hooks-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(hooks)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitBin,
		"-C", ws,
		"--git-dir", gitDir,
		"-c", "core.hooksPath="+hooks,
		"-c", "core.pager=cat",
		"-c", "diff.external=",
		"-c", "diff.textconv=",
		"-c", "alias.cat-file=",
		"cat-file", "-t", "--", name+"^{commit}",
	)
	cmd.Env = gitInspectEnv()
	cmd.Dir = ws
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	got := strings.TrimSpace(string(out))
	if got != "commit" || strings.ContainsAny(got, "\r\n") {
		return false
	}
	return true
}

// gitInspectEnv is a fresh environment. Repository hooks and inherited
// diff or textconv settings are not passed through.
func gitInspectEnv() []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/bin:/bin"
	}
	return []string{
		"PATH=" + path,
		"HOME=/",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_PAGER=cat",
		"PAGER=cat",
		"LANG=C",
	}
}
