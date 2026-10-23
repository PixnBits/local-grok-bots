package github

import (
	"errors"
	"testing"
)

func TestParsePushArgs(t *testing.T) {
	ok, err := ParsePushArgs([]string{"push", "-qu", "origin", "HEAD:refs/heads/feature"})
	if err != nil || ok.URL != "" || len(ok.Names) != 2 || ok.Names[0] != "origin" || ok.Names[1] != "HEAD:refs/heads/feature" {
		t.Fatalf("%+v %v", ok, err)
	}
	urlArgs, err := ParsePushArgs([]string{"git", "push", "https://github.com/acme/widgets.git", "feature"})
	if err != nil || urlArgs.URL != "https://github.com/acme/widgets.git" || len(urlArgs.Names) != 1 {
		t.Fatalf("%+v %v", urlArgs, err)
	}
	cases := []struct {
		args []string
		want error
	}{
		{[]string{"push", "--force", "origin"}, ErrPushForce},
		{[]string{"push", "--force-with-lease"}, ErrPushForce},
		{[]string{"push", "--force-if-includes", "origin"}, ErrPushForce},
		{[]string{"push", "-f", "origin"}, ErrPushForce},
		{[]string{"push", "origin", "+feature"}, ErrPushForce},
		{[]string{"push", "--delete", "origin", "feature"}, ErrPushDelete},
		{[]string{"push", "origin", ":feature"}, ErrPushDelete},
		{[]string{"push", "--tags"}, ErrPushTag},
		{[]string{"push", "--follow-tags"}, ErrPushTag},
		{[]string{"push", "origin", "refs/tags/v1"}, ErrPushTag},
		{[]string{"push", "--all"}, ErrPushSpec},
		{[]string{"push", "--mirror"}, ErrPushSpec},
		{[]string{"push", "--dry-run"}, ErrPushOption},
		{[]string{"push", "--signed"}, ErrPushOption},
		{[]string{"push", "--repo", "x"}, ErrPushOption},
		{[]string{"push", "git@github.com:acme/widgets.git"}, ErrPushRemote},
		{[]string{"push", "ssh://git@github.com/acme/widgets.git"}, ErrPushRemote},
		{[]string{"push", "https://user:tok@github.com/acme/widgets.git"}, ErrPushRemote},
		{[]string{"push", "https://github.com/acme/widgets.git", "https://github.com/acme/other.git"}, ErrPushRemote},
	}
	for _, tc := range cases {
		_, err := ParsePushArgs(tc.args)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%v: %v", tc.args, err)
		}
	}
	owner, repo, err := ParseGitHubRemote("https://github.com/Acme/Widgets.git")
	if err != nil || owner != "acme" || repo != "widgets" {
		t.Fatalf("remote %s %s %v", owner, repo, err)
	}
	if _, err := BranchOf("refs/heads/feature/foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := BranchOf("refs/tags/v1"); !errors.Is(err, ErrPushSpec) {
		t.Fatalf("tag branch %v", err)
	}
}
