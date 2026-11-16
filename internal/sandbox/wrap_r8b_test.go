package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A "~user" word has no slash. Git still expands it, so it is refused.
func TestGitWrapR8TildeSlashless(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	tilde := "a ~ path is not supported"
	for _, word := range []string{"~root", "~", "~nobody"} {
		// fetch and ls-remote are also stopped by the transport rules.
		for _, args := range [][]string{
			{"fetch", word},
			{"ls-remote", word},
		} {
			out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
			if err == nil {
				t.Fatalf("%v accepted\n%s", args, out)
			}
		}
		for _, args := range [][]string{
			{"remote", "add", "w", word},
			{"submodule", "add", word, "sm"},
		} {
			before := r8ConfigText(t, repo)
			out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
			if err == nil || !strings.Contains(out, tilde) {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			if r8ConfigText(t, repo) != before {
				t.Fatalf("%v wrote config", args)
			}
		}
		for _, args := range [][]string{
			{"config", "remote.w.url", word},
			{"config", "--type=path", "remote.w.url", word},
			{"remote", "set-url", "origin", word},
		} {
			gitCmd(t, repo, "config", "remote.origin.url", repo)
			before := r8ConfigText(t, repo)
			out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
			if err == nil {
				t.Fatalf("%v accepted\n%s", args, out)
			}
			if r8ConfigText(t, repo) != before {
				t.Fatalf("%v wrote config", args)
			}
		}
	}
}

// ".." in an unborn tail removes one tail segment at a time.
func TestGitWrapR8InitTailMulti(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	sub := filepath.Join(work, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, sub, nil, 20*time.Second, args...)
	}
	outsideMsg := "local path is outside the workspace"
	for _, path := range []string{
		"a/b/../../../../x",
		"a/b/c/../../../../../x",
		"a/b/../../../../../x/y",
		"a/b/c/d/../../../../../../x",
	} {
		out, err := run("init", path)
		if err == nil || !strings.Contains(out, outsideMsg) {
			t.Fatalf("init %s: %v\n%s", path, err, out)
		}
		r8NoGitOutside(t, base, work)
		if _, statErr := os.Stat(filepath.Join(base, "x")); !os.IsNotExist(statErr) {
			t.Fatalf("init %s created base/x: %v", path, statErr)
		}
	}
	out, err := run("init", "a/b/../../c/d/../../y")
	if err != nil || strings.Contains(out, outsideMsg) {
		t.Fatalf("inside multi: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "y", ".git", "HEAD")); statErr != nil {
		t.Fatalf("y missing: %v", statErr)
	}
	r8NoGitOutside(t, base, work)
}

func TestGitWrapR8InitEmptyDestination(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	wrap := installGitWrap(t, work)
	out, err := runWrapTimeout(t, wrap, work, nil, 20*time.Second, "init", "")
	if err == nil || !strings.Contains(out, "local path cannot be resolved inside the workspace") || strings.Contains(out, "outside the workspace") {
		t.Fatalf("init empty: %v\n%s", err, out)
	}
}

// Bundled clone short options: the origin value is a remote name.
func TestGitWrapR8CloneOriginBundled(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "s.txt", "SRC\n")
	wrap := installGitWrap(t, work)
	for i, flag := range []string{"-qoa/b", "-noa/b", "-qo", "-qoa@b", "-lqo-"} {
		dest := filepath.Join(work, "bad"+string(rune('a'+i)))
		args := []string{"clone", flag}
		if flag == "-qo" || flag == "-lqo-" {
			args = append(args, "a/b")
		}
		args = append(args, src, dest)
		out, err := runWrapTimeout(t, wrap, work, nil, 30*time.Second, args...)
		if err == nil || !strings.Contains(out, "remote name is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%v created %s", args, dest)
		}
	}
	dest := filepath.Join(work, "good")
	out, err := runWrapTimeout(t, wrap, work, nil, 30*time.Second, "clone", "-qoMy-Fork", src, dest)
	if err != nil || strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("good: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(dest, "remote.My-Fork.url"); !ok || got != src {
		t.Fatalf("url %q ok=%v", got, ok)
	}
}
