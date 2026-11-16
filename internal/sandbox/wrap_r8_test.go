package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func r8ConfigText(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func r8NoGitOutside(t *testing.T, root, work string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == work {
			return filepath.SkipDir
		}
		if d.IsDir() && d.Name() == ".git" {
			t.Fatalf("git directory outside the workspace: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGitWrapR8SubmoduleAddOptions(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(outside, "sub")
	outsideSHA := commitRepo(t, leaf, "f.txt", "SUBOUT\n")
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "o.txt", "ok\n")
	refInside := filepath.Join(work, "ref")
	commitRepo(t, refInside, "r.txt", "ref\n")
	wrap := installGitWrap(t, work)
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 30*time.Second, args...)
	}
	rel := "relative submodule URL is not supported"
	n := 0
	denyRel := func(args ...string) {
		t.Helper()
		n++
		dir := filepath.Join(work, "deny-"+strconv.Itoa(n))
		commitRepo(t, dir, "s.txt", "s\n")
		gitCmd(t, dir, "config", "remote.origin.url", outside)
		out, err := run(dir, args...)
		if err == nil || !strings.Contains(out, rel) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "sm")); !os.IsNotExist(statErr) {
			t.Fatalf("%v created sm: %v", args, statErr)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "dir", "sub")); !os.IsNotExist(statErr) {
			t.Fatalf("%v created dir/sub: %v", args, statErr)
		}
		if treeHas(t, dir, "SUBOUT") || gitHasObject(filepath.Join(dir, ".git"), outsideSHA) {
			t.Fatalf("%v brought outside content", args)
		}
	}
	for _, args := range [][]string{
		{"submodule", "add", "--name", "nm", "./sub", "sm"},
		{"submodule", "add", "--name=nm", "./sub", "sm"},
		{"submodule", "add", "-b", "main", "./sub", "sm"},
		{"submodule", "add", "--branch", "main", "./sub", "sm"},
		{"submodule", "add", "--branch=main", "./sub", "sm"},
		{"submodule", "add", "--depth", "1", "../sub", "sm"},
		{"submodule", "add", "--depth=1", "../sub", "sm"},
		{"submodule", "add", "--reference", refInside, "./sub", "sm"},
		{"submodule", "add", "--reference=" + refInside, "./sub", "sm"},
		{"submodule", "add", "--reference-if-able", refInside, "./sub", "sm"},
		{"submodule", "add", "--name", "nm", ".", "sm"},
		{"submodule", "add", "--name", "nm", "..", "sm"},
		{"submodule", "add", "--ref-format", "files", "./sub", "sm"},
		{"submodule", "add", "--ref-format=files", "../sub", "sm"},
		{"submodule", "add", "-j", "2", "./sub", "sm"},
		{"submodule", "add", "--jobs", "2", "./sub", "sm"},
		{"submodule", "add", "--jobs=2", "./sub", "sm"},
	} {
		denyRel(args...)
	}

	// A path value of --reference is still checked.
	n++
	dir := filepath.Join(work, "deny-"+strconv.Itoa(n))
	commitRepo(t, dir, "s.txt", "s\n")
	gitCmd(t, dir, "config", "remote.origin.url", outside)
	out, err := run(dir, "submodule", "add", "--reference", leaf, inside, "sm")
	if err == nil || !strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("outside reference: %v\n%s", err, out)
	}
	if treeHas(t, dir, "SUBOUT") {
		t.Fatal("outside reference brought outside content")
	}

	super := filepath.Join(work, "abs-super")
	commitRepo(t, super, "s.txt", "s\n")
	out, err = run(super, "submodule", "add", "--name", "nm", inside, "sm")
	if err != nil {
		t.Fatalf("absolute add: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(super, "sm", "o.txt")); statErr != nil {
		t.Fatalf("absolute submodule missing: %v\n%s", statErr, out)
	}

	superFile := filepath.Join(work, "file-super")
	commitRepo(t, superFile, "s.txt", "s\n")
	out, err = run(superFile, "submodule", "add", "--name", "nm", "file://"+inside, "sm")
	if err != nil {
		t.Fatalf("file url add: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(superFile, "sm", "o.txt")); statErr != nil {
		t.Fatalf("file url submodule missing: %v\n%s", statErr, out)
	}

	superRel := filepath.Join(work, "rel-super")
	commitRepo(t, superRel, "s.txt", "s\n")
	out, err = run(superRel, "submodule", "add", "-b", "main", inside, "./dir/sm")
	if err != nil {
		t.Fatalf("path positional: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(superRel, "dir", "sm", "o.txt")); statErr != nil {
		t.Fatalf("relative path positional missing: %v\n%s", statErr, out)
	}
}

func TestGitWrapR8TildeURL(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	outsideSHA := commitRepo(t, filepath.Join(home, "x"), "f.txt", "TILDEOUT\n")
	inside := filepath.Join(work, "src")
	insideSHA := commitRepo(t, inside, "i.txt", "INSIDE\n")
	wrap := installGitWrap(t, work)
	tilde := "a ~ path is not supported"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, []string{"HOME=" + home}, 20*time.Second, args...)
	}
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	refuse := func(args ...string) {
		t.Helper()
		before := r8ConfigText(t, repo)
		out, err := run(repo, args...)
		if err == nil || !strings.Contains(out, tilde) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
		if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) || treeHas(t, repo, "TILDEOUT") {
			t.Fatalf("%v brought outside content", args)
		}
	}
	refuse("fetch", "~/x")
	refuse("ls-remote", "~/x")
	refuse("remote", "add", "w", "~/x")
	refuse("clone", "--reference", "~/x", inside, filepath.Join(work, "ref-dest"))
	if _, statErr := os.Stat(filepath.Join(work, "ref-dest")); !os.IsNotExist(statErr) {
		t.Fatalf("reference dest exists: %v", statErr)
	}

	before := r8ConfigText(t, repo)
	for _, args := range [][]string{
		{"config", "remote.w.url", "~/x"},
		{"config", "--type=path", "remote.w.url", "~/x"},
	} {
		out, err := run(repo, args...)
		if err == nil || !strings.Contains(out, "configuration is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config\n%s", args, r8ConfigText(t, repo))
		}
	}
	out, err := run(repo, "config", "--type=path", "remote.ok.url", inside)
	if err != nil || strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("type=path inside: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.ok.url"); !ok || got != inside {
		t.Fatalf("type=path stored %q ok=%v", got, ok)
	}

	cloneDest := filepath.Join(work, "clone-tilde")
	out, err = run(work, "clone", "~/x", cloneDest)
	if err == nil || !strings.Contains(out, tilde) {
		t.Fatalf("clone: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(cloneDest); !os.IsNotExist(statErr) {
		t.Fatalf("clone dest exists: %v", statErr)
	}
	if treeHas(t, work, "TILDEOUT") {
		t.Fatal("clone brought outside content")
	}

	super := filepath.Join(work, "super")
	commitRepo(t, super, "s.txt", "s\n")
	gitCmd(t, super, "config", "remote.origin.url", home)
	out, err = run(super, "submodule", "add", "~/x", "sm")
	if err == nil || !strings.Contains(out, tilde) {
		t.Fatalf("submodule: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(super, "sm")); !os.IsNotExist(statErr) {
		t.Fatalf("submodule sm exists: %v", statErr)
	}
	if treeHas(t, super, "TILDEOUT") {
		t.Fatal("submodule brought outside content")
	}
	out, err = run(super, "submodule", "add", inside, "~/sm")
	if err == nil || !strings.Contains(out, tilde) {
		t.Fatalf("submodule path: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(super, ".gitmodules")); !os.IsNotExist(statErr) {
		t.Fatalf("submodule path wrote gitmodules: %v", statErr)
	}

	gitCmd(t, repo, "config", "remote.w.url", "~/x")
	out, err = run(repo, "fetch", "w")
	if err == nil || !strings.Contains(out, tilde) {
		t.Fatalf("stored fetch: %v\n%s", err, out)
	}
	if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) || treeHas(t, repo, "TILDEOUT") {
		t.Fatal("stored fetch brought outside content")
	}
	if gitHasObject(filepath.Join(repo, ".git"), insideSHA) {
		t.Fatal("stored fetch read the inside remote")
	}
}

func TestGitWrapR8HomeExport(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	home := filepath.Join(base, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	real := r6RealGit(t)
	dump := filepath.Join(base, "env.dump")
	argsPath := filepath.Join(base, "git.args")
	fake := filepath.Join(base, "real-git")
	r6FakeGit(t, fake, real, dump, argsPath)
	wrap := installGitWrapReal(t, work, fake, gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	cmd := exec.Command(wrap, "status")
	cmd.Dir = repo
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	envText, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	want := "HOME=" + work
	found := false
	for _, line := range strings.Split(string(envText), "\n") {
		if line == want {
			found = true
		}
		if strings.HasPrefix(line, "HOME=") && line != want {
			t.Fatalf("git saw %s\n%s", line, envText)
		}
	}
	if !found {
		t.Fatalf("git did not see %s\n%s", want, envText)
	}
	argText, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(argText), "status") {
		t.Fatalf("dump was not from status\n%s", argText)
	}
}

func TestGitWrapR8TildeNotLeading(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 20*time.Second, args...)
	}
	out, err := run(work, "init", "a~b")
	if err != nil || strings.Contains(out, "a ~ path is not supported") {
		t.Fatalf("init a~b: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(work, "a~b", ".git", "HEAD")); statErr != nil {
		t.Fatalf("a~b repo: %v", statErr)
	}
	src := filepath.Join(work, "a~src")
	sha := commitRepo(t, src, "t.txt", "TILDEMID\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	out, err = run(repo, "remote", "add", "w", src)
	if err != nil || strings.Contains(out, "a ~ path is not supported") {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	out, err = run(repo, "fetch", "w")
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(repo, ".git"), sha) {
		t.Fatal("fetch did not read the path that contains a tilde")
	}
}

func TestGitWrapR8RemoteAddOptions(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "src")
	insideSHA := commitRepo(t, inside, "i.txt", "INSIDE\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "OUTSIDE\n")
	wrap := installGitWrap(t, work)
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 20*time.Second, args...)
	}
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	nameDenied := "remote name is not allowed"
	unchanged := func(args ...string) {
		t.Helper()
		before := r8ConfigText(t, repo)
		out, err := run(repo, args...)
		if err == nil || !strings.Contains(out, nameDenied) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
		if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
			t.Fatalf("%v brought outside content", args)
		}
	}
	for _, args := range [][]string{
		{"remote", "add", "-t", "main", "a/b", inside},
		{"remote", "add", "-m", "main", "a/b", inside},
		{"remote", "add", "--track", "main", "a/b", inside},
		{"remote", "add", "--track=main", "a/b", inside},
		{"remote", "add", "--master", "main", "a/b", inside},
		{"remote", "add", "--master=main", "a/b", inside},
		{"remote", "add", "-f", "-t", "main", "a/b", inside},
		{"remote", "add", "-t", "main", "-", inside},
		{"remote", "add", "-tmain", "a/b", inside},
		{"remote", "add", "-mHEAD", "a/b", inside},
	} {
		unchanged(args...)
	}
	out, err := run(repo, "remote", "add", "-t", "main", "up", inside)
	if err != nil || strings.Contains(out, nameDenied) {
		t.Fatalf("remote add -t up: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.up.url"); !ok || got != inside {
		t.Fatalf("up url %q ok=%v", got, ok)
	}
	out, err = run(repo, "remote", "add", "-tmain", "side", inside)
	if err != nil {
		t.Fatalf("remote add -tmain: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.side.url"); !ok || got != inside {
		t.Fatalf("side url %q ok=%v", got, ok)
	}

	// fetch -t still names the remote. The following word is not an option value.
	tracked := filepath.Join(work, "tracked")
	commitRepo(t, tracked, "t.txt", "t\n")
	gitCmd(t, tracked, "remote", "add", "origin", outside)
	out, err = run(tracked, "fetch", "-t", "origin")
	if err == nil || !strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("fetch -t: %v\n%s", err, out)
	}
	if gitHasObject(filepath.Join(tracked, ".git"), outsideSHA) {
		t.Fatal("fetch -t brought outside content")
	}
	gitCmd(t, tracked, "remote", "set-url", "origin", inside)
	out, err = run(tracked, "fetch", "-t", "origin")
	if err != nil || strings.Contains(out, nameDenied) {
		t.Fatalf("fetch -t inside: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(tracked, ".git"), insideSHA) {
		t.Fatal("fetch -t did not read the inside remote")
	}
	out, err = run(tracked, "fetch", "-o", "a/b", "origin")
	if err != nil || strings.Contains(out, nameDenied) {
		t.Fatalf("fetch -o: %v\n%s", err, out)
	}
}

func TestGitWrapR8CloneOriginName(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(work, "src")
	commitRepo(t, src, "s.txt", "SRC\n")
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, work, nil, 30*time.Second, args...)
	}
	nameDenied := "remote name is not allowed"
	n := 0
	refuse := func(args ...string) {
		t.Helper()
		n++
		dest := filepath.Join(work, "bad-"+strconv.Itoa(n))
		all := append(append([]string{}, args...), src, dest)
		out, err := run(all...)
		if err == nil || !strings.Contains(out, nameDenied) {
			t.Fatalf("%v: %v\n%s", all, err, out)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%v created %s: %v", all, dest, statErr)
		}
	}
	refuse("clone", "-o", "a/b")
	refuse("clone", "-o", "-")
	refuse("clone", "-oa/b")
	refuse("clone", "--origin=a/b")
	refuse("clone", "--origin", "a@b")

	accept := func(remote string, args ...string) {
		t.Helper()
		n++
		dest := filepath.Join(work, "ok-"+strconv.Itoa(n))
		all := append(append([]string{}, args...), src, dest)
		out, err := run(all...)
		if err != nil || strings.Contains(out, nameDenied) {
			t.Fatalf("%v: %v\n%s", all, err, out)
		}
		if _, statErr := os.Stat(filepath.Join(dest, "s.txt")); statErr != nil {
			t.Fatalf("%v missing clone: %v\n%s", all, statErr, out)
		}
		got, ok := gitLocalGet(dest, "remote."+remote+".url")
		if !ok || got != src {
			t.Fatalf("%v remote %s url %q ok=%v", all, remote, got, ok)
		}
		if _, ok := gitLocalGet(dest, "remote.origin.url"); remote != "origin" && ok {
			t.Fatalf("%v also wrote origin", all)
		}
	}
	accept("up", "clone", "-o", "up")
	accept("My-Fork", "clone", "--origin=My-Fork")
	accept("My-Fork", "clone", "-oMy-Fork")
}

func TestGitWrapR8RenameDash(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "i.txt", "i\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	gitCmd(t, repo, "remote", "add", "origin", inside)
	wrap := installGitWrap(t, work)
	for _, args := range [][]string{
		{"remote", "rename", "origin", "-"},
		{"remote", "rename", "origin", "-x"},
		{"remote", "rename", "--", "origin", "-"},
	} {
		before := r8ConfigText(t, repo)
		out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
		if err == nil || !strings.Contains(out, "remote name is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
		if gitCmdOut(t, repo, "remote") != "origin" {
			t.Fatalf("%v renamed the remote", args)
		}
	}
}

func TestGitWrapR8SlashlessURL(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "i.txt", "INSIDE\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "OUTSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	if err := os.Symlink(outside, filepath.Join(repo, "outlink")); err != nil {
		t.Fatal(err)
	}
	insideName := filepath.Join(repo, "insidedir")
	commitRepo(t, insideName, "n.txt", "NAMED\n")
	namedSHA := gitCmdOut(t, insideName, "rev-parse", "HEAD")
	colonName := "example.com:repo.git"
	if err := os.Symlink(outside, filepath.Join(repo, colonName)); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	unchanged := func(needle string, args ...string) {
		t.Helper()
		before := r8ConfigText(t, repo)
		out, err := run(args...)
		if err == nil || !strings.Contains(out, needle) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
		if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
			t.Fatalf("%v brought outside content", args)
		}
	}
	unchanged("local path is outside the workspace", "remote", "add", "w", "outlink")
	gitCmd(t, repo, "remote", "add", "origin", inside)
	unchanged("local path is outside the workspace", "remote", "set-url", "origin", "outlink")
	if got, ok := gitLocalGet(repo, "remote.origin.url"); !ok || got != inside {
		t.Fatalf("origin changed to %q ok=%v", got, ok)
	}
	unchanged("configuration is not allowed", "config", "remote.w.url", "outlink")

	out, err := run("config", "remote.keep.url", "nosuch")
	if err != nil || strings.Contains(out, "configuration is not allowed") || strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("missing slashless: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.keep.url"); !ok || got != "nosuch" {
		t.Fatalf("nosuch stored %q ok=%v", got, ok)
	}
	out, err = run("config", "remote.named.url", "insidedir")
	if err != nil {
		t.Fatalf("inside slashless: %v\n%s", err, out)
	}
	out, err = run("fetch", "named")
	if err != nil {
		t.Fatalf("fetch named: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(repo, ".git"), namedSHA) {
		t.Fatal("fetch named did not read the inside directory")
	}
	if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
		t.Fatal("outside content arrived")
	}
	out, err = run("config", "remote.colon.url", colonName)
	if err != nil || strings.Contains(out, "configuration is not allowed") || strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("colon value: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.colon.url"); !ok || got != colonName {
		t.Fatalf("colon stored %q ok=%v", got, ok)
	}
}

func TestGitWrapR8SurvivorBareSlash(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	outsideSHA := commitRepo(t, outside, "o.txt", "OUTSIDE\n")
	insideDir := filepath.Join(work, "indir")
	insideSHA := commitRepo(t, insideDir, "i.txt", "INSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	if err := os.Symlink(outside, filepath.Join(repo, "rellink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(insideDir, filepath.Join(repo, "inlink")); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	before := r8ConfigText(t, repo)
	out, err := run("remote", "add", "w", "rellink/")
	if err == nil || !strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	out, err = run("config", "remote.w.url", "rellink/")
	if err == nil || !strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("config: %v\n%s", err, out)
	}
	if r8ConfigText(t, repo) != before {
		t.Fatalf("write changed config\n%s", r8ConfigText(t, repo))
	}
	if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
		t.Fatal("outside content arrived")
	}
	out, err = run("remote", "add", "ok", "inlink/")
	if err != nil {
		t.Fatalf("inside remote add: %v\n%s", err, out)
	}
	out, err = run("config", "remote.ok2.url", "inlink/")
	if err != nil || strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("inside config: %v\n%s", err, out)
	}
	for _, name := range []string{"ok", "ok2"} {
		out, err = run("fetch", name)
		if err != nil {
			t.Fatalf("fetch %s: %v\n%s", name, err, out)
		}
	}
	if !gitHasObject(filepath.Join(repo, ".git"), insideSHA) {
		t.Fatal("inside trailing slash was not fetched")
	}
	if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
		t.Fatal("outside content arrived")
	}
}

func TestGitWrapR8ConfigKeyShape(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "i.txt", "i\n")
	wrap := installGitWrap(t, work)
	run := func(key, val string) string {
		t.Helper()
		before := r8ConfigText(t, repo)
		out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, "config", key, val)
		if err == nil || !strings.Contains(out, "configuration is not allowed") {
			t.Fatalf("%q: %v\n%s", key, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%q wrote config", key)
		}
		return out
	}
	out := run("remote.a/b.url", inside)
	if !strings.Contains(out, "configuration is not allowed: remote.a?b.url") {
		t.Fatalf("slash key: %s", out)
	}
	if strings.Contains(out, "remote.ab.url") {
		t.Fatalf("slash was deleted: %s", out)
	}
	out = run("remote.é.url", inside)
	if !strings.Contains(out, "configuration is not allowed: remote.??.url") || strings.Contains(out, "é") {
		t.Fatalf("non-ascii key: %s", out)
	}
	if strings.Contains(out, "remote..url") {
		t.Fatalf("non-ascii bytes were deleted: %s", out)
	}
	out = run("remote.a\tb.url", inside)
	if strings.Contains(out, "\t") || !strings.Contains(out, "configuration is not allowed: remote.a?b.url") {
		t.Fatalf("tab key: %q", out)
	}
	out = run("remote.a\nb.url", inside)
	denial, _, _ := strings.Cut(out, "\n")
	if denial != "git config denied: configuration is not allowed: remote.a?b.url" {
		t.Fatalf("newline key: %q", out)
	}
	out = run("remote.a*b.url", inside)
	if !strings.Contains(out, "configuration is not allowed: remote.a*b.url") {
		t.Fatalf("star key: %s", out)
	}
	longKey := strings.Repeat("q", 122)
	out = run(longKey, inside)
	const prefix = "configuration is not allowed: "
	idx := strings.Index(out, prefix)
	if idx < 0 {
		t.Fatalf("long key: %s", out)
	}
	shown, _, _ := strings.Cut(out[idx+len(prefix):], "\n")
	if shown != strings.Repeat("q", 100) {
		t.Fatalf("long key length %d %q", len(shown), shown)
	}
}

func TestGitWrapR8InitTail(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	jail := filepath.Join(base, "jail")
	work := filepath.Join(jail, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, []string{"GIT_TERMINAL_PROMPT=0"}, 20*time.Second, args...)
	}
	fresh := func(name string) string {
		t.Helper()
		dir := filepath.Join(work, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	gitDir := func(path string) {
		t.Helper()
		rel, err := filepath.Rel(work, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("%s is outside %s", path, work)
		}
		if _, statErr := os.Stat(filepath.Join(path, ".git", "HEAD")); statErr != nil {
			t.Fatalf("%s missing .git: %v", path, statErr)
		}
	}
	outsideMsg := "local path is outside the workspace"
	unresolved := "local path cannot be resolved inside the workspace"
	accept := func(dir, path, created string) {
		t.Helper()
		out, err := run(dir, "init", path)
		if err != nil || strings.Contains(out, outsideMsg) || strings.Contains(out, unresolved) {
			t.Fatalf("init %s: %v\n%s", path, err, out)
		}
		gitDir(created)
		r8NoGitOutside(t, base, work)
	}
	refuseOutside := func(dir, path string, absent ...string) {
		t.Helper()
		out, err := run(dir, "init", path)
		if err == nil || !strings.Contains(out, outsideMsg) {
			t.Fatalf("init %s: %v\n%s", path, err, out)
		}
		for _, p := range absent {
			if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
				t.Fatalf("init %s created %s: %v", path, p, statErr)
			}
		}
		r8NoGitOutside(t, base, work)
	}

	sub := fresh("sub")
	accept(sub, "zz/../x", filepath.Join(sub, "x"))
	sub2 := fresh("sub2")
	accept(sub2, "a/b/../../x", filepath.Join(sub2, "x"))
	sub3 := fresh("sub3")
	accept(sub3, "zz/../../newtop", filepath.Join(work, "newtop"))

	sub4 := fresh("sub4")
	out, err := run(sub4, "init", "a/../..")
	if strings.Contains(out, outsideMsg) || strings.Contains(out, unresolved) {
		t.Fatalf("missing a/../..: %v\n%s", err, out)
	}
	r8NoGitOutside(t, base, work)
	sub5 := fresh("sub5")
	if err := os.MkdirAll(filepath.Join(sub5, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	accept(sub5, "a/../..", work)

	sub6 := fresh("sub6")
	refuseOutside(sub6, "zz/../../../tmp-out", filepath.Join(jail, "tmp-out"), filepath.Join(base, "tmp-out"))
	refuseOutside(sub6, "zz/../../../..", filepath.Join(base, ".git"), filepath.Join(jail, ".git"))
	refuseOutside(sub6, "a/../../..", filepath.Join(jail, ".git"), filepath.Join(base, ".git"))

	linked := filepath.Join(jail, "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	sub7 := fresh("sub7")
	if err := os.Symlink(linked, filepath.Join(sub7, "link")); err != nil {
		t.Fatal(err)
	}
	refuseOutside(sub7, "link/../x", filepath.Join(jail, "x"), filepath.Join(linked, "x"), filepath.Join(sub7, "x"))
	refuseOutside(sub7, "zz/../link/../x", filepath.Join(jail, "x"), filepath.Join(linked, "x"))

	inner := filepath.Join(work, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	sub8 := fresh("sub8")
	if err := os.Symlink(inner, filepath.Join(sub8, "link")); err != nil {
		t.Fatal(err)
	}
	accept(sub8, "link/../work/x", filepath.Join(work, "work", "x"))

	sub9 := fresh("sub9")
	if err := os.WriteFile(filepath.Join(sub9, "nofile"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = run(sub9, "init", "nofile/x")
	if err == nil || !strings.Contains(out, unresolved) || strings.Contains(out, outsideMsg) {
		t.Fatalf("nofile: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(sub9, "x")); !os.IsNotExist(statErr) {
		t.Fatalf("nofile created x: %v", statErr)
	}
	r8NoGitOutside(t, base, work)
}

func TestGitWrapR8SurvivorColon(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "i.txt", "i\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	before := r8ConfigText(t, repo)
	out, err := run("remote", "add", "a:b", inside)
	if err == nil || !strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	out, err = run("config", "remote.a:b.url", inside)
	if err == nil || !strings.Contains(out, "configuration is not allowed: remote.a?b.url") {
		t.Fatalf("config: %v\n%s", err, out)
	}
	if r8ConfigText(t, repo) != before {
		t.Fatal("colon name wrote config")
	}
}

func TestGitWrapR8SurvivorTildeName(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	inside := filepath.Join(work, "src")
	commitRepo(t, inside, "i.txt", "i\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	before := r8ConfigText(t, repo)
	out, err := run("remote", "add", "a~b", inside)
	if err == nil || !strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("remote add: %v\n%s", err, out)
	}
	out, err = run("config", "remote.a~b.url", inside)
	if err == nil || !strings.Contains(out, "configuration is not allowed") {
		t.Fatalf("config: %v\n%s", err, out)
	}
	if r8ConfigText(t, repo) != before {
		t.Fatal("tilde name wrote config")
	}
}

func TestGitWrapR8SurvivorUpperName(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(work, "src")
	insideSHA := commitRepo(t, inside, "i.txt", "INSIDE\n")
	outsideSHA := commitRepo(t, outside, "o.txt", "OUTSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	for _, name := range []string{"My-Fork", "A", "UP"} {
		out, err := run("remote", "add", name, inside)
		if err != nil || strings.Contains(out, "remote name is not allowed") {
			t.Fatalf("remote add %s: %v\n%s", name, err, out)
		}
		out, err = run("fetch", name)
		if err != nil {
			t.Fatalf("fetch %s: %v\n%s", name, err, out)
		}
		out, err = run("ls-remote", name)
		if err != nil || !strings.Contains(out, insideSHA) {
			t.Fatalf("ls-remote %s: %v\n%s", name, err, out)
		}
	}
	if !gitHasObject(filepath.Join(repo, ".git"), insideSHA) {
		t.Fatal("fetch did not read the inside remote")
	}
	if gitHasObject(filepath.Join(repo, ".git"), outsideSHA) {
		t.Fatal("outside content arrived")
	}
	other := filepath.Join(work, "other")
	commitRepo(t, other, "o.txt", "o\n")
	out, err := runWrapTimeout(t, wrap, other, nil, 20*time.Second, "config", "remote.My-Fork.url", inside)
	if err != nil || strings.Contains(out, "configuration is not allowed") || strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("config My-Fork: %v\n%s", err, out)
	}
	out, err = runWrapTimeout(t, wrap, other, nil, 20*time.Second, "fetch", "My-Fork")
	if err != nil {
		t.Fatalf("fetch My-Fork: %v\n%s", err, out)
	}
	if !gitHasObject(filepath.Join(other, ".git"), insideSHA) {
		t.Fatal("config remote.My-Fork.url was not fetched")
	}
}

func TestGitWrapR8SurvivorSymlinkDir(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	sub := filepath.Join(work, "sub")
	inner := filepath.Join(work, "inner")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inner, filepath.Join(sub, "link")); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	out, err := runWrapTimeout(t, wrap, sub, []string{"GIT_TERMINAL_PROMPT=0"}, 20*time.Second, "init", "link/../work/x")
	if err != nil || strings.Contains(out, "local path is outside the workspace") || strings.Contains(out, "local path cannot be resolved inside the workspace") {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(work, "work", "x", ".git", "HEAD")); statErr != nil {
		t.Fatalf("repo: %v", statErr)
	}
	r8NoGitOutside(t, base, work)
}

func TestGitWrapR8SurvivorNonLastFile(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(sub, "nofile"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	out, err := runWrapTimeout(t, wrap, sub, []string{"GIT_TERMINAL_PROMPT=0"}, 20*time.Second, "init", "nofile/x")
	if err == nil || !strings.Contains(out, "local path cannot be resolved inside the workspace") || strings.Contains(out, "local path is outside the workspace") {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "x")); !os.IsNotExist(statErr) {
		t.Fatalf("created x: %v", statErr)
	}
	r8NoGitOutside(t, base, work)
}
