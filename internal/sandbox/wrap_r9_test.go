package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func r9Run(t *testing.T, wrap, dir, home, oldpwd string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrap, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"OLDPWD=" + oldpwd,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func r9EmptyRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, dir, "init", "-q", "-b", "main")
}

func r9Section(dir, name string) bool {
	b, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "[remote \""+name+"\"]")
}

func r9SymRef(t *testing.T, dir, name string) string {
	t.Helper()
	ref := "refs/remotes/" + name + "/HEAD"
	cmd := exec.Command("git", "-C", dir, "symbolic-ref", ref)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("symbolic-ref %s: %v\n%s", ref, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Bad remote names are refused for option clusters, unique abbreviations, and a name after "--".
func TestGitWrapR9NameForms(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	wrap := installGitWrap(t, work)
	names := []string{"a/b", "é", "a@b", "-", "x;y", "$x"}
	type addForm struct {
		label string
		args  func(name, url string) []string
	}
	adds := []addForm{
		{"tra", func(name, url string) []string {
			return []string{"remote", "add", "--tra", "main", name, url}
		}},
		{"mas", func(name, url string) []string {
			return []string{"remote", "add", "--mas", "main", name, url}
		}},
		{"ft", func(name, url string) []string {
			return []string{"remote", "add", "-ft", "main", name, url}
		}},
		{"fm", func(name, url string) []string {
			return []string{"remote", "add", "-fm", "main", name, url}
		}},
	}
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 20*time.Second, args...)
	}
	for _, name := range names {
		for _, form := range adds {
			t.Run("add-"+form.label+"/"+name, func(t *testing.T) {
				before := r8ConfigText(t, repo)
				args := form.args(name, src)
				out, err := run(repo, args...)
				if err == nil || !strings.Contains(out, "remote name is not allowed") {
					t.Fatalf("%v: %v\n%s", args, err, out)
				}
				if r8ConfigText(t, repo) != before {
					t.Fatalf("%v wrote config", args)
				}
				if r9Section(repo, name) {
					t.Fatalf("%v wrote remote %s", args, name)
				}
			})
		}
	}
	n := 0
	cloneForm := func(label string, args func(name, src, dest string) []string, name string) {
		t.Helper()
		n++
		dest := filepath.Join(work, "cl", fmt.Sprintf("%d", n))
		all := args(name, src, dest)
		out, err := run(work, all...)
		if err == nil || (!strings.Contains(out, "option is not allowed") && !strings.Contains(out, "remote name is not allowed")) {
			t.Fatalf("%v: %v\n%s", all, err, out)
		}
		if r9Section(dest, name) || r9Section(src, name) {
			t.Fatalf("%v wrote remote %s", all, name)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%v created %s: %v", all, dest, statErr)
		}
	}
	for _, name := range names {
		cloneForm("orig-eq/"+name, func(name, src, dest string) []string {
			return []string{"clone", "--orig=" + name, src, dest}
		}, name)
		cloneForm("orig-sep/"+name, func(name, src, dest string) []string {
			return []string{"clone", "--orig", name, src, dest}
		}, name)
	}
	for _, name := range []string{"--x", "-x"} {
		cloneForm("orig-eq-dash/"+name, func(name, src, dest string) []string {
			return []string{"clone", "--orig=" + name, src, dest}
		}, name)
		cloneForm("orig-sep-dash/"+name, func(name, src, dest string) []string {
			return []string{"clone", "--orig", name, src, dest}
		}, name)
	}

	renamed := filepath.Join(work, "renamed")
	commitRepo(t, renamed, "r.txt", "r\n")
	gitCmd(t, renamed, "remote", "add", "origin", src)
	before := r8ConfigText(t, renamed)
	args := []string{"remote", "rename", "--", "origin", "--x"}
	out, err := run(renamed, args...)
	if err == nil || (!strings.Contains(out, "remote name is not allowed") && !strings.Contains(out, "option is not allowed")) {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	if r8ConfigText(t, renamed) != before || r9Section(renamed, "--x") {
		t.Fatalf("rename wrote config\n%s", r8ConfigText(t, renamed))
	}
	if gitCmdOut(t, renamed, "remote") != "origin" {
		t.Fatal("rename changed the remote")
	}
}

// Accepted remote add spellings still write the remote.
func TestGitWrapR9RemoteAddAccepted(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	wrap := installGitWrap(t, work)
	names := []string{"origin2", "My-Fork", "a.b"}
	type form struct {
		label string
		flags []string
		kind  string
	}
	forms := []form{
		{"-t", []string{"-t", "main"}, "track"},
		{"-tmain", []string{"-tmain"}, "track"},
		{"--track", []string{"--track", "main"}, "track"},
		{"--track=", []string{"--track=main"}, "track"},
		{"--tra", []string{"--tra", "main"}, "track"},
		{"--tra=", []string{"--tra=main"}, "track"},
		{"--tr", []string{"--tr", "main"}, "track"},
		{"-m", []string{"-m", "main"}, "master"},
		{"-mmain", []string{"-mmain"}, "master"},
		{"--master", []string{"--master", "main"}, "master"},
		{"--master=", []string{"--master=main"}, "master"},
		{"--ma", []string{"--ma", "main"}, "master"},
		{"--mas=", []string{"--mas=main"}, "master"},
		{"-f-t", []string{"-f", "-t", "main"}, "fetch"},
		{"-ft", []string{"-ft", "main"}, "fetch"},
		{"-fft", []string{"-fft", "main"}, "fetch"},
		{"-tf", []string{"-tf"}, "plain"},
		{"--no-tags", []string{"--no-tags"}, "notags"},
		{"--tags", []string{"--tags"}, "tags"},
		{"--mirror=fetch", []string{"--mirror=fetch"}, "mirror"},
		{"--mirror", []string{"--mirror"}, "mirrorplain"},
		{"--mirr=push", []string{"--mirr=push"}, "mirrorpush"},
		{"--no-fe", []string{"--no-fe"}, "plain"},
		{"--no-track", []string{"--no-track"}, "plain"},
		{"--", []string{"--"}, "plain"},
	}
	for i, form := range forms {
		name := names[i%len(names)]
		t.Run(form.label+"/"+name, func(t *testing.T) {
			repo := filepath.Join(work, "ok", fmt.Sprintf("%d", i))
			r9EmptyRepo(t, repo)
			args := append([]string{"remote", "add"}, form.flags...)
			args = append(args, name, src)
			out, err := runWrapTimeout(t, wrap, repo, nil, 30*time.Second, args...)
			if strings.Contains(out, "remote name is not allowed") || strings.Contains(out, "option is not allowed") {
				t.Fatalf("%v refused\n%s", args, out)
			}
			got, ok := gitLocalGet(repo, "remote."+name+".url")
			if !ok || got != src {
				t.Fatalf("%v url %q ok=%v err=%v\n%s", args, got, ok, err, out)
			}
			if form.kind != "fetch" && err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			switch form.kind {
			case "track", "fetch":
				fetch, ok := gitLocalGet(repo, "remote."+name+".fetch")
				if !ok || !strings.Contains(fetch, "refs/heads/main:") {
					t.Fatalf("%v fetch %q ok=%v", args, fetch, ok)
				}
			case "master":
				if got := r9SymRef(t, repo, name); got != "refs/remotes/"+name+"/main" {
					t.Fatalf("%v symref %s", args, got)
				}
			case "notags":
				tag, ok := gitLocalGet(repo, "remote."+name+".tagopt")
				if !ok || tag != "--no-tags" {
					t.Fatalf("%v tagopt %q ok=%v", args, tag, ok)
				}
			case "tags":
				tag, ok := gitLocalGet(repo, "remote."+name+".tagopt")
				if !ok || tag != "--tags" {
					t.Fatalf("%v tagopt %q ok=%v", args, tag, ok)
				}
			case "mirror":
				fetch, ok := gitLocalGet(repo, "remote."+name+".fetch")
				if !ok || fetch != "+refs/*:refs/*" {
					t.Fatalf("%v fetch %q ok=%v", args, fetch, ok)
				}
			case "mirrorplain":
				fetch, ok := gitLocalGet(repo, "remote."+name+".fetch")
				mirror, mok := gitLocalGet(repo, "remote."+name+".mirror")
				if !ok || fetch != "+refs/*:refs/*" || !mok || mirror != "true" {
					t.Fatalf("%v fetch %q mirror %q", args, fetch, mirror)
				}
			case "mirrorpush":
				mirror, ok := gitLocalGet(repo, "remote."+name+".mirror")
				if !ok || mirror != "true" {
					t.Fatalf("%v mirror %q ok=%v", args, mirror, ok)
				}
			}
		})
	}
}

// "=" forms take the value in the same word. The next word is the remote name.
func TestGitWrapR9TrackEquals(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	wrap := installGitWrap(t, work)
	flags := []struct {
		label string
		flag  string
		kind  string
	}{
		{"track", "--track=main", "track"},
		{"master", "--master=main", "master"},
		{"tra", "--tra=main", "track"},
		{"mas", "--mas=main", "master"},
	}
	names := []string{"origin2", "My-Fork", "a.b"}
	n := 0
	for _, form := range flags {
		for _, name := range names {
			n++
			repo := filepath.Join(work, "ok", fmt.Sprintf("%d", n))
			r9EmptyRepo(t, repo)
			args := []string{"remote", "add", form.flag, name, src}
			out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
			if err != nil || strings.Contains(out, "remote name is not allowed") || strings.Contains(out, "option is not allowed") {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			got, ok := gitLocalGet(repo, "remote."+name+".url")
			if !ok || got != src {
				t.Fatalf("%v url %q ok=%v", args, got, ok)
			}
			switch form.kind {
			case "track":
				fetch, ok := gitLocalGet(repo, "remote."+name+".fetch")
				if !ok || !strings.Contains(fetch, "refs/heads/main:") || strings.Contains(fetch, "refs/heads/"+name+":") {
					t.Fatalf("%v fetch %q", args, fetch)
				}
			case "master":
				if got := r9SymRef(t, repo, name); got != "refs/remotes/"+name+"/main" {
					t.Fatalf("%v symref %s", args, got)
				}
			}
		}
		repo := filepath.Join(work, "bad")
		r9EmptyRepo(t, repo)
		before := r8ConfigText(t, repo)
		args := []string{"remote", "add", form.flag, "a/b", src}
		out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
		if err == nil || !strings.Contains(out, "remote name is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before || r9Section(repo, "a/b") {
			t.Fatalf("%v wrote config", args)
		}
	}
}

// A long option that is a prefix of --origin is refused. The exact spelling is checked as a name.
func TestGitWrapR9CloneOriginPrefix(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "s.txt", "SRC\n")
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, work, nil, 30*time.Second, args...)
	}
	n := 0
	refusePrefix := func(args ...string) {
		t.Helper()
		n++
		dest := filepath.Join(work, "bad", fmt.Sprintf("%d", n))
		all := append(append([]string{}, args...), src, dest)
		out, err := run(all...)
		if err == nil || !strings.Contains(out, "option is not allowed") {
			t.Fatalf("%v: %v\n%s", all, err, out)
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("%v created dest: %v", all, statErr)
		}
		if r9Section(dest, "origin2") || r9Section(dest, "a/b") {
			t.Fatalf("%v wrote a remote", all)
		}
	}
	for _, prefix := range []string{"--o", "--or", "--ori", "--orig", "--origi"} {
		refusePrefix("clone", "-q", prefix, "origin2")
		refusePrefix("clone", "-q", prefix+"=origin2")
		refusePrefix("clone", "-q", prefix, "a/b")
		refusePrefix("clone", "-q", prefix+"=a/b")
	}
	for _, args := range [][]string{
		{"clone", "-q", "--no-origin=a/b"},
		{"clone", "-q", "--no-orig", "a/b"},
		{"clone", "-q", "--no-or", "origin2"},
		{"clone", "-q", "--no-origin", "origin2"},
	} {
		n++
		dest := filepath.Join(work, "bad", fmt.Sprintf("%d", n))
		all := append(append([]string{}, args...), src, dest)
		out, err := run(all...)
		if err == nil {
			t.Fatalf("%v accepted\n%s", all, out)
		}
		if r9Section(dest, "a/b") || r9Section(dest, "origin2") {
			t.Fatalf("%v wrote a renamed remote\n%s", all, out)
		}
	}

	good := filepath.Join(work, "good-origin")
	out, err := run("clone", "-q", "--origin=origin2", src, good)
	if err != nil || strings.Contains(out, "option is not allowed") || strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("exact origin: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(good, "remote.origin2.url"); !ok || got != src {
		t.Fatalf("origin2 url %q ok=%v", got, ok)
	}

	noOrigin := filepath.Join(work, "good-no-origin")
	out, err = run("clone", "-q", "--no-origin", src, noOrigin)
	if err != nil || strings.Contains(out, "option is not allowed") {
		t.Fatalf("no-origin: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(noOrigin, "remote.origin.url"); !ok || got != src {
		t.Fatalf("no-origin url %q ok=%v", got, ok)
	}
	if _, ok := gitLocalGet(noOrigin, "remote.origin2.url"); ok {
		t.Fatal("no-origin wrote origin2")
	}

	obj := filepath.Join(work, "object-format")
	out, err = run("clone", "--object-format=sha1", src, obj)
	if err == nil {
		t.Fatal("object-format was accepted")
	}
	if strings.Contains(out, "option is not allowed") {
		t.Fatalf("object-format refused by the wrapper\n%s", out)
	}
	if r9Section(obj, "origin") {
		t.Fatal("object-format wrote origin")
	}
}

// Words after "--" on remote are names, including a word that starts with "-".
func TestGitWrapR9RemoteDashDash(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	gitCmd(t, repo, "remote", "add", "origin", src)
	wrap := installGitWrap(t, work)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	for _, args := range [][]string{
		{"remote", "add", "--", "--x", src},
		{"remote", "add", "--", "-x", src},
		{"remote", "remove", "--", "--x"},
		{"remote", "rename", "--", "origin", "--x"},
	} {
		before := r8ConfigText(t, repo)
		out, err := run(args...)
		if err == nil || !strings.Contains(out, "remote name is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
	}
	out, err := run("remote", "add", "--", "origin2", src)
	if err != nil || strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("add after --: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.origin2.url"); !ok || got != src {
		t.Fatalf("origin2 url %q ok=%v", got, ok)
	}
	out, err = run("remote", "remove", "--", "origin")
	if err != nil || strings.Contains(out, "remote name is not allowed") {
		t.Fatalf("remove after --: %v\n%s", err, out)
	}
	if gitCmdOut(t, repo, "remote") != "origin2" {
		t.Fatal("remove -- origin left origin in place")
	}
}

// A spelling git rejects for remote add is refused before a name is read.
func TestGitWrapR9RemoteAddUnknown(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	repo := filepath.Join(work, "repo")
	r9EmptyRepo(t, repo)
	wrap := installGitWrap(t, work)
	for _, args := range [][]string{
		{"remote", "add", "--t", "main", "a/b", src},
		{"remote", "add", "--m", "main", "a/b", src},
		{"remote", "add", "--no-t", "origin2", src},
		{"remote", "add", "--bogus", "origin2", src},
		{"remote", "add", "-fx", "main", "a/b", src},
		{"remote", "add", "-b", "main", "a/b", src},
		{"remote", "add", "-o", "origin2", src},
	} {
		before := r8ConfigText(t, repo)
		out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
		if err == nil || !strings.Contains(out, "option is not allowed") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if r8ConfigText(t, repo) != before {
			t.Fatalf("%v wrote config", args)
		}
	}
}

// A leading "~" on a URL positional is refused. A tilde later in the word is not.
func TestGitWrapR9LeadingTilde(t *testing.T) {
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
	commitRepo(t, filepath.Join(home, "x"), "homefile", "TILDEHOME\n")
	src := filepath.Join(work, "src")
	commitRepo(t, src, "i.txt", "INSIDE\n")
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "r\n")
	gitCmd(t, repo, "remote", "add", "origin", src)
	wrap := installGitWrap(t, work)
	tilde := "a ~ path is not supported"
	words := []string{"~", "~root", "~USER", "~x", "~+", "~-"}
	snapshot := func(root string) string {
		t.Helper()
		var b strings.Builder
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			b.WriteString(rel)
			b.WriteByte('\n')
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	homeBefore := snapshot(home)
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return r9Run(t, wrap, dir, home, home, args...)
	}
	for _, word := range words {
		for _, args := range [][]string{
			{"fetch", word},
			{"pull", word},
			{"push", word},
			{"ls-remote", word},
			{"fetch", "--", word},
			{"remote", "add", "origin2", word},
			{"remote", "add", "origin2", "--", word},
			{"remote", "set-url", "origin", word},
			{"clone", word, filepath.Join(work, "cl")},
			{"submodule", "add", word, "sm"},
		} {
			dir := repo
			if args[0] == "clone" {
				dir = work
			}
			before := r8ConfigText(t, repo)
			out, err := run(dir, args...)
			if err == nil || !strings.Contains(out, tilde) {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			if r8ConfigText(t, repo) != before {
				t.Fatalf("%v wrote config", args)
			}
			if _, statErr := os.Stat(filepath.Join(work, "cl")); !os.IsNotExist(statErr) {
				t.Fatalf("%v created clone dest: %v", args, statErr)
			}
			if _, statErr := os.Stat(filepath.Join(repo, "sm")); !os.IsNotExist(statErr) {
				t.Fatalf("%v created sm: %v", args, statErr)
			}
			if _, statErr := os.Stat(filepath.Join(repo, ".gitmodules")); !os.IsNotExist(statErr) {
				t.Fatalf("%v wrote gitmodules: %v", args, statErr)
			}
			if treeHas(t, work, "TILDEHOME") {
				t.Fatalf("%v read the outside home", args)
			}
		}
	}
	if snapshot(home) != homeBefore {
		t.Fatal("outside home changed")
	}
	out, err := run(repo, "remote", "add", "side", "a~b")
	if err != nil || strings.Contains(out, tilde) {
		t.Fatalf("remote add a~b: %v\n%s", err, out)
	}
	if got, ok := gitLocalGet(repo, "remote.side.url"); !ok || got != "a~b" {
		t.Fatalf("a~b url %q ok=%v", got, ok)
	}
	out, err = run(repo, "fetch", "a~b")
	if strings.Contains(out, tilde) {
		t.Fatalf("fetch a~b refused for a tilde\n%s", out)
	}
	if err == nil {
		t.Fatalf("fetch a~b succeeded\n%s", out)
	}
}

// git init uses one sentence when a component cannot be walked, and another when the path resolves outside.
func TestGitWrapR9InitPathText(t *testing.T) {
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
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	wrap := installGitWrap(t, work)
	unresolved := "git init denied: local path cannot be resolved inside the workspace"
	outsideMsg := "git init denied: local path is outside the workspace"
	run := func(dir string, args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, dir, nil, 20*time.Second, args...)
	}
	exact := func(dir, path, want, absent string) {
		t.Helper()
		out, err := run(dir, "init", path)
		if err == nil {
			t.Fatalf("init %s accepted\n%s", path, out)
		}
		line, _, _ := strings.Cut(out, "\n")
		if line != want {
			t.Fatalf("init %s stderr %q", path, out)
		}
		if strings.Contains(out, absent) {
			t.Fatalf("init %s also said %q\n%s", path, absent, out)
		}
		r8NoGitOutside(t, base, work)
	}
	sub := filepath.Join(work, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "reg"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	exact(sub, "reg/x", unresolved, outsideMsg)
	exact(sub, "reg/../x", unresolved, outsideMsg)
	if err := os.Symlink(filepath.Join(base, "missing-target"), filepath.Join(sub, "dang")); err != nil {
		t.Fatal(err)
	}
	exact(sub, "dang/x", unresolved, outsideMsg)
	exact(sub, "dang/../x", unresolved, outsideMsg)
	if os.Geteuid() != 0 {
		nox := filepath.Join(sub, "nox")
		if err := os.Mkdir(nox, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(nox, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(nox, 0o755) })
		exact(sub, "nox/x", unresolved, outsideMsg)
	}

	if err := os.Symlink(outside, filepath.Join(sub, "link")); err != nil {
		t.Fatal(err)
	}
	exact(sub, "link/child", outsideMsg, unresolved)
	exact(sub, "../../outside/child", outsideMsg, unresolved)
	exact(work, "", unresolved, outsideMsg)

	out, err := run(sub, "init", "inside-ok")
	if err != nil || strings.Contains(out, unresolved) || strings.Contains(out, outsideMsg) {
		t.Fatalf("inside init: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(sub, "inside-ok", ".git", "HEAD")); statErr != nil {
		t.Fatalf("inside repo: %v", statErr)
	}
	r8NoGitOutside(t, base, work)
}
