package permbroker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func gitInitMain(t *testing.T, ws string) {
	t.Helper()
	gitRun(t, ws, "init", "-b", "main")
	gitRun(t, ws, "add", "--", "README.md")
	gitRun(t, ws, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "init")
}

func TestCeilingAbsolutePathspec(t *testing.T) {
	ws := r9Repo(t)
	mustWrite(t, filepath.Join(ws, "src", "a.txt"), "a\n")
	mustWrite(t, filepath.Join(ws, "plain", "b.txt"), "b\n")
	mustWrite(t, filepath.Join(ws, ".vscode", "tasks.json"), "{}\n")
	mustWrite(t, filepath.Join(ws, "newdir", "credentials"), "x\n")
	mustWrite(t, filepath.Join(ws, "deep", "a", ".env"), "x\n")
	if err := os.Symlink(ws, filepath.Join(ws, "rootlink")); err != nil {
		t.Fatal(err)
	}
	absFile := filepath.Join(ws, "README.md")
	asks := []string{
		"git add " + ws,
		"git add " + ws + "/",
		"git add " + ws + "/.",
		"git add " + ws + "/src/..",
		"git add " + absFile,
		"git add -- " + ws,
		"git commit -m x " + ws,
		"git commit -m x -- " + ws + "/",
		"git commit -m x -- ':/'",
		"git commit -m x -- '*'",
		"git commit -m x -- .",
		"git add .vscode",
		"git add newdir",
		"git add deep",
		"git add deep/a/",
		"git add rootlink",
	}
	for _, cmd := range asks {
		r9Ask(t, ws, cmd)
	}
	r9Allow(t, ws, LevelMedium, "git add README.md")
	r9Allow(t, ws, LevelMedium, "git add src/a.txt")
	r9Allow(t, ws, LevelMedium, "git add src")
	r9Allow(t, ws, LevelMedium, "git add plain")
	r9Allow(t, ws, LevelMedium, "git commit -m x README.md")
	r9Allow(t, ws, LevelMedium, "git commit -m x src/a.txt")

	locked := filepath.Join(ws, "locked")
	mustWrite(t, filepath.Join(locked, "a.txt"), "a\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if os.Geteuid() != 0 {
		if _, err := os.ReadDir(locked); err == nil {
			t.Fatal("locked directory was readable")
		}
		r9Ask(t, ws, "git add locked")
		r9Ask(t, ws, "git commit -m x locked")
	}
}

func TestCeilingShowConfirmsCommit(t *testing.T) {
	skipIfJailWrapper(t)
	ws := r9Repo(t)
	gitInitMain(t, ws)
	blobFile := filepath.Join(ws, "blob.txt")
	mustWrite(t, blobFile, "x\n")
	blob := gitRun(t, ws, "hash-object", "-w", "--", "blob.txt")
	if len(blob) < 12 {
		t.Fatalf("blob id %q", blob)
	}
	gitRun(t, ws, "tag", "light", blob)
	gitRun(t, ws, "-c", "user.name=Test", "-c", "user.email=test@example.com", "tag", "-a", "annot", blob, "-m", "note")
	gitRun(t, ws, "update-ref", "refs/custom/rb", blob)
	gitRun(t, ws, "tag", "release", "HEAD")
	descFull := "x-0-g" + blob
	descShort := "dsc-1-g" + blob[:12]
	gitRun(t, ws, "branch", descFull, "HEAD")
	gitRun(t, ws, "branch", descShort, "HEAD")

	refs := []string{"light", "annot", "refs/tags/annot", "refs/custom/rb", descFull, descShort}
	forms := []string{
		"git show --stat %s",
		"git show --name-only %s",
		"git show --name-status %s",
		"git show --stat --format=%B %s",
		"git show %s --stat",
	}
	for _, ref := range refs {
		for _, form := range forms {
			r9Ask(t, ws, sprintfShow(form, ref))
		}
	}
	r9Allow(t, ws, LevelLow, "git show --stat HEAD")
	r9Allow(t, ws, LevelLow, "git show --name-only HEAD")
	r9Allow(t, ws, LevelLow, "git show --stat HEAD -- README.md")
	r9Allow(t, ws, LevelLow, "git show --stat main")
	r9Allow(t, ws, LevelLow, "git show --stat release")
	r9Ask(t, ws, "git cat-file -t HEAD")
}

func TestCeilingShowNoReplaceObjectsAsks(t *testing.T) {
	skipIfJailWrapper(t)
	ws := r9Repo(t)
	gitInitMain(t, ws)
	mustWrite(t, filepath.Join(ws, "secret.txt"), "secret-blob\n")
	gitRun(t, ws, "add", "--", "secret.txt")
	gitRun(t, ws, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-m", "secret")
	blob := gitRun(t, ws, "rev-parse", "HEAD:secret.txt")
	if len(blob) < 12 {
		t.Fatalf("blob id %q", blob)
	}
	gitRun(t, ws, "update-ref", "refs/tags/blobtag", blob)
	gitRun(t, ws, "update-ref", "refs/replace/"+blob, "HEAD")
	r9Allow(t, ws, LevelLow, "git show --stat blobtag")
	r9Ask(t, ws, "git --no-replace-objects show --stat blobtag")
}

func sprintfShow(form, ref string) string {
	return strings.Replace(form, "%s", ref, 1)
}
