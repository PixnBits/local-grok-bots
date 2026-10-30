package permbroker

import "testing"

func TestParseLiteralSimpleCommand(t *testing.T) {
	got := ParseCommand(`git "status"`)
	if !got.Eligible || got.Compound || got.Reason != "" {
		t.Fatalf("%+v", got)
	}
	if !argvEqual(got.Argv, []string{"git", "status"}) {
		t.Fatalf("argv %q", got.Argv)
	}
	redir := ParseCommand("echo ok >/dev/null 2>&1")
	if !redir.Eligible || !argvEqual(redir.Argv, []string{"echo", "ok"}) {
		t.Fatalf("%+v", redir)
	}
	quoted := ParseCommand(`echo "foo # bar"`)
	if !quoted.Eligible || !argvEqual(quoted.Argv, []string{"echo", "foo # bar"}) {
		t.Fatalf("%+v", quoted)
	}
}

func TestParseAsksForAnythingElse(t *testing.T) {
	cases := []string{
		`echo $(id)`,
		`echo $HOME`,
		`git status && true`,
		`git status | head`,
		`echo *`,
		`echo ~/x`,
		`FOO=1 git status`,
		`sudo git status`,
		`bash -c 'git status'`,
		"git status # note",
		"git status\\\n--short",
		"git status\r--short",
		"git status\u037e true",
	}
	for _, src := range cases {
		got := ParseCommand(src)
		if got.Eligible {
			t.Fatalf("eligible %q %+v", src, got)
		}
	}
	compound := ParseCommand(`git status && true`)
	if !compound.Compound {
		t.Fatalf("compound flag %+v", compound)
	}
}
