package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func r11HubOff() string {
	return gitWrap(gitWrapOpts{
		Grant:  true,
		Hub:    false,
		Bridge: true,
		Repos:  []string{"acme/widgets"},
		Name:   "Ada",
		Email:  "bot@localhost",
	})
}

func r11Text(t *testing.T, script string, args ...string) string {
	t.Helper()
	return runGitWrap(t, script, args...)
}

// Exact option names win. The listed spellings are accepted. A unique
// prefix still resolves, and an unknown or ambiguous spelling is refused.
func TestGitWrapR11ExactNames(t *testing.T) {
	script := r11HubOff()
	option := "option is not allowed"
	url := "https://github.com/acme/widgets.git"
	accept := func(args ...string) {
		t.Helper()
		text := r11Text(t, script, args...)
		if strings.Contains(text, option) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	accept("fetch", "--prune")
	accept("fetch", "--no-prune")
	accept("fetch", "-p")
	accept("fetch", "--prune-t")
	accept("pull", "--ff")
	accept("pull", "--verify")
	accept("pull", "--no-verify")
	accept("pull", "--no-strategy")
	accept("pull", "--summary")
	accept("pull", "--no-summary")
	accept("ls-remote", "--heads")
	accept("ls-remote", "--no-heads")
	accept("clone", "--no-reference", "file:///work/fixture", "dest")
	accept("clone", "--naked", "file:///work/fixture", "dest")
	accept("clone", "--no-naked", "file:///work/fixture", "dest")

	// A separate strategy value is consumed. The attached form leaves the next word.
	text := r11Text(t, script, "pull", "--strategy", url)
	if strings.Contains(text, option) || strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("strategy value: %s", text)
	}
	text = r11Text(t, script, "pull", "--strategy=ort", url)
	if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("strategy=: %s", text)
	}
	text = r11Text(t, script, "pull", "--strategy="+url)
	if strings.Contains(text, option) || strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("attached strategy: %s", text)
	}
	text = r11Text(t, script, "pull", "--ff", url)
	if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("ff: %s", text)
	}

	text = r11Text(t, script, "pull", "--stra")
	if !strings.Contains(text, option) {
		t.Fatalf("ambiguous: %s", text)
	}
	text = r11Text(t, script, "fetch", "--not-a-real-option")
	if !strings.Contains(text, option) {
		t.Fatalf("unknown: %s", text)
	}
}

// Every user-facing --no-* of submodule add and update is accepted, as is update --fetch.
func TestGitWrapR11SubmoduleOpts(t *testing.T) {
	script := r11HubOff()
	option := "option is not allowed"
	url := "https://github.com/acme/widgets.git"
	accept := func(args ...string) {
		t.Helper()
		text := r11Text(t, script, args...)
		if strings.Contains(text, option) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, flag := range []string{
		"--no-branch", "--no-force", "--no-quiet", "--no-progress",
		"--no-reference", "--no-ref-format", "--no-dissociate",
		"--no-name", "--no-depth",
	} {
		accept("submodule", "add", flag, "file:///work/fixture")
	}
	text := r11Text(t, script, "submodule", "add", "--no-force", url)
	if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("no-force: %s", text)
	}
	for _, flag := range []string{
		"--no-force", "--no-init", "--no-remote", "--no-recursive",
		"--no-fetch", "--fetch", "--no-checkout", "--no-merge",
		"--no-rebase", "--no-reference", "--no-ref-format",
		"--no-dissociate", "--no-depth", "--no-jobs",
		"--no-recommend-shallow", "--no-quiet", "--no-progress",
		"--no-require-init", "--no-single-branch", "--no-filter",
	} {
		accept("submodule", "update", flag)
	}
	text = r11Text(t, script, "submodule", "update", "--no-jobs=1")
	if !strings.Contains(text, option) {
		t.Fatalf("no-jobs=: %s", text)
	}
	text = r11Text(t, script, "submodule", "update", "--fetch=1")
	if !strings.Contains(text, option) {
		t.Fatalf("fetch=: %s", text)
	}
}

// set-head --auto queries the named remote and is a fetch for the grant decision.
func TestGitWrapR11SetHeadAuto(t *testing.T) {
	skipIfJailWrapper(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal("git is not installed")
	}
	work := t.TempDir()
	repo := filepath.Join(work, "repo")
	commitRepo(t, repo, "r.txt", "R\n")
	gitCmd(t, repo, "remote", "add", "origin", "https://github.com/acme/widgets.git")
	opts := gitWrapOpts{
		Grant: true, Hub: false, Bridge: true,
		Repos: []string{"acme/widgets"},
		Name:  "Ada", Email: "bot@localhost",
	}
	wrap := installGitWrapWith(t, work, opts)
	run := func(args ...string) (string, error) {
		t.Helper()
		return runWrapTimeout(t, wrap, repo, nil, 20*time.Second, args...)
	}
	for _, args := range [][]string{
		{"remote", "set-head", "origin", "-a"},
		{"remote", "set-head", "-a", "origin"},
		{"remote", "set-head", "origin", "--auto"},
		{"remote", "set-head", "--auto", "origin"},
		{"remote", "set-head", "origin", "--au"},
		{"remote", "set-head", "--au", "origin"},
		{"remote", "set-head", "origin", "-da"},
		{"remote", "set-head", "-ad", "origin"},
	} {
		out, err := run(args...)
		if err == nil || !strings.Contains(out, GitHubGrantOff) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, args := range [][]string{
		{"remote", "set-head", "origin", "main"},
		{"remote", "set-head", "origin", "-d"},
		{"remote", "set-head", "origin", "--delete"},
		{"remote", "set-head", "origin", "--no-auto"},
	} {
		out, err := run(args...)
		if strings.Contains(out, GitHubGrantOff) {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	opts.Hub = true
	opts.Bridge = false
	wrapOn := installGitWrapWith(t, work, opts)
	out, err := runWrapTimeout(t, wrapOn, repo, nil, 20*time.Second, "remote", "set-head", "origin", "--auto")
	if err == nil || !strings.Contains(out, GitHubBridgeDown) {
		t.Fatalf("bridge: %v\n%s", err, out)
	}
}

// archive --remote names a repository and is a fetch for the grant decision.
func TestGitWrapR11ArchiveRemote(t *testing.T) {
	script := r11HubOff()
	url := "https://github.com/acme/widgets.git"
	for _, args := range [][]string{
		{"archive", "--remote", url, "HEAD"},
		{"archive", "--remote=" + url, "HEAD"},
		{"archive", "--rem", url, "HEAD"},
		{"archive", "--rem=" + url, "HEAD"},
		{"archive", "--format", "--remote", url, "HEAD"},
		{"archive", "--prefix", "--remote=" + url, "HEAD"},
	} {
		text := r11Text(t, script, args...)
		if !strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	text := r11Text(t, script, "archive", "--remote=https://github.com/other/nope.git", "HEAD")
	if !strings.Contains(text, RepoNotAvailable) || strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("off-list: %s", text)
	}
	on := gitWrap(gitWrapOpts{
		Grant: true, Hub: true, Bridge: false,
		Repos: []string{"acme/widgets"},
		Name:  "Ada", Email: "bot@localhost",
	})
	text = r11Text(t, on, "archive", "--remote="+url, "HEAD")
	if !strings.Contains(text, GitHubBridgeDown) {
		t.Fatalf("bridge: %s", text)
	}
	text = r11Text(t, script, "archive", "--list")
	if strings.Contains(text, GitHubGrantOff) {
		t.Fatalf("list: %s", text)
	}
	// A prefix of output or exec is not the exact name, so the next word is still scanned.
	for _, args := range [][]string{
		{"archive", "--out", "--remote", url, "HEAD"},
		{"archive", "--ex", "--remote", url, "HEAD"},
	} {
		text = r11Text(t, script, args...)
		if !strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	// output and exec take the next word. That word is not a remote.
	for _, args := range [][]string{
		{"archive", "--output", "--remote", url, "HEAD"},
		{"archive", "--exec", "--remote", url, "HEAD"},
	} {
		text = r11Text(t, script, args...)
		if strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// A long option name with a character outside the allowed set is refused.
func TestGitWrapR11LongCharset(t *testing.T) {
	body := between(t, gitWrapScript, "long_closed() {", "\nset_head_queries() {")
	if !strings.Contains(body, "A long option name is letters, digits, and \"-\".") {
		t.Fatal("charset rule missing")
	}
	pat := strings.Index(body, "*[!A-Za-z0-9-]*")
	res := strings.Index(body, "long_resolve")
	if pat < 0 || res < 0 || pat > res {
		t.Fatal("charset check is not before long_resolve")
	}
	text := r11Text(t, r11HubOff(), "fetch", "--dry.run")
	if !strings.Contains(text, "option is not allowed") {
		t.Fatalf("odd character: %s", text)
	}
}

// end_opts starts clear at the option loop.
func TestGitWrapR11EndOpts(t *testing.T) {
	start := strings.Index(gitWrapScript, "end_opts starts clear")
	if start < 0 {
		t.Fatal("end_opts init missing")
	}
	rest := gitWrapScript[start:]
	forAt := strings.Index(rest, "for arg in \"$@\"; do")
	if forAt < 0 {
		t.Fatal("option loop missing")
	}
	window := rest[:forAt]
	if !strings.Contains(window, "\n    end_opts=\n") || strings.Contains(window, "end_opts=1") {
		t.Fatal("end_opts is not cleared at the start of the option loop")
	}
}

// The option parse marks a remote-add fetch. The later scan is a separate mark.
func TestGitWrapR11RemoteFetchEarly(t *testing.T) {
	long := between(t, gitWrapScript, "remote_add_long() {", "\nremote_add_short() {")
	short := between(t, gitWrapScript, "remote_add_short() {", "\n# Long options for one subcommand")
	fn := between(t, gitWrapScript, "mark_remote_fetch() {", "\n# remote add long options")
	if !strings.Contains(long, "mark_remote_fetch") {
		t.Fatal("remote_add_long does not mark a fetch")
	}
	if !strings.Contains(short, "mark_remote_fetch") {
		t.Fatal("remote_add_short does not mark a fetch")
	}
	if !strings.Contains(fn, "remote_fetches=1") {
		t.Fatal("mark_remote_fetch does not set remote_fetches")
	}
}

func TestGitWrapR11RemoteFetchLater(t *testing.T) {
	late := between(t, gitWrapScript, "remote add fetches with", "if [ -z \"$remote_fetches\" ]")
	if !strings.Contains(late, "remote_add_is_fetch") || strings.Count(late, "mark_remote_fetch") < 2 {
		t.Fatal("later detector does not mark both fetch forms")
	}
}

// Each live resolver arm refuses on its own. Command-naming options stay with
// refuse_command_opt. Submodule recursion stays with refuse_submodule_opt.
func TestGitWrapR11ResolverArms(t *testing.T) {
	resolve := between(t, gitWrapScript, "long_resolve() {", "\nlong_apply() {")
	if !strings.Contains(resolve, "\"$2\")") || !strings.Contains(resolve, "return 0") {
		t.Fatal("exact option name does not win")
	}
	apply := between(t, gitWrapScript, "long_apply() {", "\nlong_closed() {")
	for _, needle := range []string{
		"config|config-env)",
		"sv_name\" != origin",
		"reference|reference-if-able|separate-git-dir|template|bundle-uri)",
		"lr_canon\" = all",
	} {
		if !strings.Contains(apply, needle) {
			t.Fatalf("long_apply missing %s", needle)
		}
	}
	script := r11HubOff()
	option := "option is not allowed"
	submod := "submodule path is outside the workspace"
	tilde := "a ~ path is not supported"
	configDenied := "configuration is not allowed"
	nameDenied := "remote name is not allowed"
	outside := "local path is outside the workspace"
	url := "https://github.com/acme/widgets.git"

	t.Run("config-separate", func(t *testing.T) {
		text := r11Text(t, script, "clone", "--confi", "url.example.insteadOf=https://example.com", "file:///work/fixture", "dest")
		if !strings.Contains(text, configDenied) || strings.Contains(text, option) {
			t.Fatal(text)
		}
	})
	t.Run("config-env", func(t *testing.T) {
		if !strings.Contains(apply, "config|config-env)") {
			t.Fatal("config-env left the config arm")
		}
	})
	t.Run("path-attached", func(t *testing.T) {
		text := r11Text(t, script, "clone", "--templat=~root", "file:///work/fixture", "dest")
		if !strings.Contains(text, tilde) {
			t.Fatal(text)
		}
	})
	t.Run("path-separate", func(t *testing.T) {
		text := r11Text(t, script, "clone", "--reference-i", "~root", "file:///work/fixture", "dest")
		if !strings.Contains(text, tilde) {
			t.Fatal(text)
		}
	})
	t.Run("flag-equals", func(t *testing.T) {
		text := r11Text(t, script, "fetch", "--dry-run=1")
		if !strings.Contains(text, option) {
			t.Fatal(text)
		}
	})
	t.Run("opt-attached", func(t *testing.T) {
		text := r11Text(t, script, "pull", "--rebase=file:///etc/passwd")
		if !strings.Contains(text, outside) || strings.Contains(text, option) {
			t.Fatal(text)
		}
	})
	t.Run("opt-next", func(t *testing.T) {
		text := r11Text(t, script, "pull", "--rebase", url)
		if strings.Contains(text, option) || !strings.Contains(text, GitHubGrantOff) {
			t.Fatal(text)
		}
	})
	t.Run("origin-prefix", func(t *testing.T) {
		text := r11Text(t, script, "clone", "--orig=a/b", "file:///work/fixture", "dest")
		if !strings.Contains(text, option) {
			t.Fatal(text)
		}
	})
	t.Run("origin-equals", func(t *testing.T) {
		loop := between(t, gitWrapScript, "clone|fetch|pull|ls-remote|remote|submodule)", "remote_rest=$remote_names")
		if !strings.Contains(loop, "--origin=*)") || !strings.Contains(loop, "remote_name_ok \"${arg#*=}\" || say_remote_name") {
			t.Fatal("origin= name check missing")
		}
		text := r11Text(t, script, "clone", "--origin=a/b", "file:///work/fixture", "dest")
		if !strings.Contains(text, nameDenied) {
			t.Fatal(text)
		}
	})
	t.Run("push-ambiguous", func(t *testing.T) {
		body := between(t, gitWrapScript, "push_is_repo() {", "\npush_tilde() {")
		if !strings.Contains(body, "pr_hits\" -eq 1") {
			t.Fatal("push_is_repo does not require one hit")
		}
		// Every non-unique prefix of repo is also a prefix of receive-pack,
		// so refuse_command_opt refuses it. It is not treated as --repo.
		text := r11Text(t, script, "push", "--re=~root")
		if strings.Contains(text, tilde) || !strings.Contains(text, option) {
			t.Fatal(text)
		}
	})
	t.Run("upload-pack", func(t *testing.T) {
		for _, args := range [][]string{
			{"clone", "--upload-pac=x", "file:///work/fixture", "dest"},
			{"fetch", "--multiple"},
			{"fetch", "--mul"},
			{"pull", "--exec=git-upload-pack"},
			{"ls-remote", "--exec"},
		} {
			text := r11Text(t, script, args...)
			if !strings.Contains(text, option) {
				t.Fatalf("%v: %s", args, text)
			}
		}
	})
	t.Run("recurse", func(t *testing.T) {
		for _, args := range [][]string{
			{"clone", "--recurse"},
			{"fetch", "--shallow-sub"},
		} {
			text := r11Text(t, script, args...)
			if !strings.Contains(text, submod) {
				t.Fatalf("%v: %s", args, text)
			}
		}
	})
	t.Run("all-prefix", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Fatal("git is not installed")
		}
		if st, err := os.Stat("/lgb/bin/git"); err == nil && !st.IsDir() {
			t.Skip("skipped in the jail, where git on PATH is the wrapper")
		}
		work := t.TempDir()
		local := filepath.Join(work, "local")
		commitRepo(t, local, "l.txt", "L\n")
		repo := filepath.Join(work, "repo")
		commitRepo(t, repo, "r.txt", "R\n")
		gitCmd(t, repo, "remote", "add", "origin", local)
		gitCmd(t, repo, "remote", "add", "up", url)
		wrap := installGitWrapWith(t, work, gitWrapOpts{
			Grant: true, Hub: false, Bridge: true,
			Repos: []string{"acme/widgets"},
			Name:  "Ada", Email: "bot@localhost",
		})
		out, err := runWrapTimeout(t, wrap, repo, nil, 20*time.Second, "fetch", "--al")
		if err == nil || !strings.Contains(out, GitHubGrantOff) {
			t.Fatalf("fetch --al: %v\n%s", err, out)
		}
	})
}
