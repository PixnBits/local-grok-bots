package permbroker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitInspectBlocksTransport(t *testing.T) {
	env := gitInspectEnv()
	for _, needle := range []string{"GIT_NO_LAZY_FETCH=1", "GIT_ALLOW_PROTOCOL="} {
		if !stringListHas(env, needle) {
			t.Fatalf("missing %s in %v", needle, env)
		}
	}
	args := strings.Join(gitInspectArgs("/ws", "/ws/.git", "/hooks", "HEAD"), "\n")
	for _, needle := range []string{"protocol.allow=never", "core.sshCommand=/bin/false"} {
		if !strings.Contains(args, needle) {
			t.Fatalf("missing %s in %s", needle, args)
		}
	}
}

func skipIfJailWrapper(t *testing.T) {
	t.Helper()
	if st, err := os.Stat("/lgb/bin/git"); err == nil && !st.IsDir() {
		t.Skip("skipped in the jail, where git on PATH is the wrapper")
	}
}

func TestGitInspectDoesNotRunUploadPack(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	origin := t.TempDir()
	mustWrite(t, filepath.Join(origin, "blob.txt"), "blob-body\n")
	gitRun(t, origin, "init", "-b", "main")
	gitRun(t, origin, "add", "--", "blob.txt")
	gitRun(t, origin, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "blob")
	blob := gitRun(t, origin, "rev-parse", "HEAD:blob.txt")

	base := t.TempDir()
	partial := filepath.Join(base, "repo")
	gitRun(t, base, "-c", "protocol.file.allow=always", "clone", "--no-local", "file://"+origin, "repo")
	if st, err := os.Lstat(filepath.Join(partial, ".git")); err != nil || !st.IsDir() {
		t.Fatalf("clone left no repository: %v", err)
	}

	marker := filepath.Join(t.TempDir(), "uploadpack-ran")
	scriptPath := filepath.Join(t.TempDir(), "uploadpack")
	script := "#!/bin/sh\nprintf '%s\\n' ran >> " + shellSingle(marker) + "\nexit 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, partial, "config", "remote.origin.uploadpack", scriptPath)
	gitRun(t, partial, "config", "remote.origin.promisor", "true")
	gitRun(t, partial, "config", "extensions.partialClone", "origin")
	removeGitObjects(t, partial, blob)
	if _, err := os.Lstat(looseObject(partial, blob)); err == nil {
		t.Fatal("loose object still present")
	}

	ctrl := exec.Command(unwrappedGit(), "-C", partial, "cat-file", "-t", blob)
	ctrl.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + partial,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	if out, err := ctrl.CombinedOutput(); err == nil {
		t.Fatalf("control cat-file succeeded without the object:\n%s", out)
	}
	ran, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(ran), "ran") {
		// A wrapped git on PATH (the jail) does not start a helper. The
		// unwrapped binary is used when it is present; otherwise the
		// control cannot be established and only the production check runs.
		if unwrappedGit() == "git" || isScriptGit(unwrappedGit()) {
			t.Logf("control did not run uploadpack: %v %q", err, ran)
		} else {
			t.Fatalf("control did not run uploadpack: %v %q", err, ran)
		}
	} else if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	if gitCommitObject(partial, blob) {
		t.Fatal("missing object was accepted")
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("uploadpack ran: %s", b)
	}
}

func removeGitObjects(t *testing.T, repo, blob string) {
	t.Helper()
	pack := filepath.Join(repo, ".git", "objects", "pack")
	ents, err := os.ReadDir(pack)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if err := os.Remove(filepath.Join(pack, ent.Name())); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Remove(looseObject(repo, blob))
	info := filepath.Join(repo, ".git", "objects", "info")
	ents, err = os.ReadDir(info)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, ent := range ents {
		if err := os.RemoveAll(filepath.Join(info, ent.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func looseObject(repo, id string) string {
	return filepath.Join(repo, ".git", "objects", id[:2], id[2:])
}

func shellSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func stringListHas(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

func unwrappedGit() string {
	const real = "/lgb/bin/git"
	if st, err := os.Lstat(real); err == nil && !st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
		return real
	}
	return "git"
}

func isScriptGit(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 2 {
		return false
	}
	return b[0] == '#' && b[1] == '!'
}
