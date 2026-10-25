package github

import "testing"

func TestNormalizeRepos(t *testing.T) {
	got, err := NormalizeRepos([]string{"PixnBits/Scratch", "pixnbits/scratch", "acme/widgets"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "pixnbits/scratch" || got[1] != "acme/widgets" {
		t.Fatalf("%#v", got)
	}
	for _, bad := range []string{"", "noslash", "a/b/c", "../x", "a/../b", ".git/x", "a/.git", "a/b.git", "-a/b", "a/-b", "has space/repo", "owner/repo\n"} {
		if _, err := NormalizeRepo(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestCommitAuthor(t *testing.T) {
	name, email, err := CommitAuthor("Ada", "", "")
	if err != nil || name != "Ada" || email != "Ada@users.noreply" {
		t.Fatalf("%s %s %v", name, email, err)
	}
	name, email, err = CommitAuthor("Ada", "ci-bot", "{name}@users.noreply.github.com")
	if err != nil || name != "ci-bot" || email != "ci-bot@users.noreply.github.com" {
		t.Fatalf("template %s %s %v", name, email, err)
	}
	name, email, err = CommitAuthor("Ada", "", "bots@users.noreply")
	if err != nil || email != "bots@users.noreply" || name != "Ada" {
		t.Fatalf("literal %s %s %v", name, email, err)
	}
	for _, bot := range []string{"", "Ada Bot", "Ada;touch", "Ada'x", "Ada$HOME", "Ada\n", "../Ada"} {
		if _, _, err := CommitAuthor(bot, "", ""); err == nil {
			t.Fatalf("accepted bot %q", bot)
		}
	}
	if _, _, err := CommitAuthor("Ada", "ok", "';touch /tmp/x'@users.noreply"); err == nil {
		t.Fatal("accepted injection template")
	}
	if _, _, err := CommitAuthor("Ada", "bad name", ""); err == nil {
		t.Fatal("accepted unsafe author_name")
	}
}
