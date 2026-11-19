package sandbox

import (
	"strings"
	"testing"
)

// After "--", pull and remote update still refuse a word that starts with "-".
// remote add, remote rename, and remote remove keep the name check
// (TestGitWrapR9RemoteDashDash).
func TestGitWrapR10DashDashOptions(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	option := "option is not allowed"
	submod := "submodule path is outside the workspace"
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"pull", "--", "--upload-pack=git-upload-pack"}, option},
		{[]string{"pull", "--", "--recurse-submodules=yes"}, submod},
		{[]string{"pull", "--", "-o", "serveropt"}, option},
		{[]string{"remote", "update", "--", "--prune"}, option},
	}
	for _, tc := range cases {
		text := runGitWrap(t, script, tc.args...)
		if !strings.Contains(text, tc.want) {
			t.Fatalf("%v: %s", tc.args, text)
		}
	}
}

// Long options resolve by unique prefix. A resolved config option uses the
// same assignment check as --config. Unknown and ambiguous spellings are refused.
func TestGitWrapR10LongAllow(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	assign := "url.example.insteadOf=https://example.com"
	key := "url.example.insteadof"
	configDenied := "configuration is not allowed"
	option := "option is not allowed"
	for _, flag := range []string{"--con=", "--conf=", "--confi=", "--config="} {
		text := runGitWrap(t, script, "clone", flag+assign, "file:///work/fixture", "dest")
		if !strings.Contains(text, configDenied) || !strings.Contains(text, key) {
			t.Fatalf("%s: %s", flag, text)
		}
		if strings.Contains(text, option) {
			t.Fatalf("%s fell through as an unknown option: %s", flag, text)
		}
	}
	text := runGitWrap(t, script, "clone", "--c=1", "file:///work/fixture", "dest")
	if !strings.Contains(text, option) || strings.Contains(text, configDenied) {
		t.Fatalf("ambiguous clone config prefix: %s", text)
	}
	for _, args := range [][]string{
		{"clone", "--foo", "file:///work/fixture", "dest"},
		{"fetch", "--au"},
		{"pull", "--co"},
		{"ls-remote", "--s"},
		{"submodule", "add", "--r", "name"},
		{"submodule", "update", "--re"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, option) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// A unique prefix of fetch, and a short cluster that contains f, is a fetch
// for the bridge decision.
func TestGitWrapR10RemoteFetchPrefix(t *testing.T) {
	script := gitWrap(gitWrapOpts{
		Grant:  true,
		Hub:    false,
		Bridge: true,
		Repos:  []string{"acme/widgets"},
		Name:   "Ada",
		Email:  "bot@localhost",
	})
	url := "https://github.com/acme/widgets.git"
	for _, args := range [][]string{
		{"remote", "add", "--fe", "origin", url},
		{"remote", "add", "--fet", "origin", url},
		{"remote", "add", "--fetc", "origin", url},
		{"remote", "add", "-ft", "main", "origin", url},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
	for _, args := range [][]string{
		{"remote", "add", "origin", url},
		{"remote", "add", "--no-fe", "origin", url},
	} {
		text := runGitWrap(t, script, args...)
		if strings.Contains(text, GitHubGrantOff) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// remote add refuses a non-unique prefix, an unknown long option, and "=" on a flag.
func TestGitWrapR10RemoteAddBranches(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	option := "option is not allowed"
	for _, args := range [][]string{
		{"remote", "add", "--no-t", "origin", "https://example.com/a.git"},
		{"remote", "add", "--foo", "origin", "https://example.com/a.git"},
		{"remote", "add", "--tags=x", "origin", "https://example.com/a.git"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, option) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// A unique prefix of push --repo is checked for a leading "~".
// vet, vet_local, and check_local_arg keep their leading "~" arms beside
// the positional and --repo checks.
func TestGitWrapR10PushRepoPrefix(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	tilde := "a ~ path is not supported"
	for _, args := range [][]string{
		{"push", "--rep=~root"},
		{"push", "--repo", "~root"},
		{"push", "--repo=~root"},
	} {
		text := runGitWrap(t, script, args...)
		if !strings.Contains(text, tilde) {
			t.Fatalf("%v: %s", args, text)
		}
	}
}

// The unwalkable ".." step in init_vet refuses with say_file_path.
func TestGitWrapR10InitWalkSaysPath(t *testing.T) {
	iv := between(t, gitWrapScript, "init_vet() {", "\nguard_init() {")
	needle := `iv_cur=$(cd -P -- "$iv_cur/.." 2>/dev/null && pwd -P) || say_file_path`
	if !strings.Contains(iv, needle) {
		t.Fatal("init_vet .. walk does not refuse with say_file_path")
	}
}
