package github

import "testing"

func TestRepoConfigAllowsOrdinaryFiles(t *testing.T) {
	ordinary := "" +
		"[core]\n" +
		"\trepositoryformatversion = 0\n" +
		"\tfilemode = true\n" +
		"\tbare = false\n" +
		"\tlogallrefupdates = true\n" +
		"[remote \"origin\"]\n" +
		"\turl = https://github.com/acme/widgets.git\n" +
		"\tfetch = +refs/heads/*:refs/remotes/origin/*\n" +
		"[branch \"feature\"]\n" +
		"\tremote = origin\n" +
		"\tmerge = refs/heads/feature\n" +
		"[user]\n" +
		"\tname = Ada\n" +
		"\temail = ada@localhost\n"
	if RepoConfigDenied(ordinary) {
		t.Fatal("ordinary config denied")
	}
	if RepoConfigDenied("") || RepoConfigDenied("\n# comment\n\n") {
		t.Fatal("empty config denied")
	}
}

func TestRepoConfigDeniesHostileKeys(t *testing.T) {
	base := "[core]\n\tbare = false\n"
	cases := []string{
		"[url \"http://127.0.0.1/x/\"]\n\tinsteadOf = https://github.com/acme/widgets.git\n",
		"[URL \"http://127.0.0.1/x/\"]\n\tINSTEADOF = https://github.com/\n",
		"[credential]\n\thelper = /tmp/mark\n",
		"[credential \"https://github.com\"]\n\tusername = x\n",
		"[http]\n\tproxy = http://127.0.0.1:9\n",
		"[http \"https://github.com\"]\n\textraHeader = X: y\n",
		"[core]\n\tfsmonitor = /tmp/mark\n",
		"[core]\n\tFsMonitor = /tmp/mark\n",
		"[Core]\n\taskPass = /tmp/mark\n",
		"[gpg]\n\tprogram = /tmp/mark\n",
		"[gpg \"ssh\"]\n\tprogram = /tmp/mark\n",
		"[include]\n\tpath = /tmp/other\n",
		"[includeIf \"gitdir:/work/**\"]\n\tpath = /tmp/other\n",
		"[core]\n\tsshCommand = /tmp/mark\n",
		"[core]\n\thooksPath = /tmp/hooks\n",
		"[alias]\n\tpush = !/tmp/mark\n",
		"[filter \"evil\"]\n\tclean = /tmp/mark\n\tsmudge = /tmp/mark\n",
		"[diff]\n\texternal = /tmp/mark\n",
		"[remote \"origin\"]\n\tpushurl = http://attacker/stolen.git\n",
		"not a section\n",
		"[core]\n\tthis is bad\n",
		"[core]\n\tbare = false\\\n",
	}
	for _, snippet := range cases {
		if !RepoConfigDenied(base+snippet) && !RepoConfigDenied(snippet) {
			t.Fatalf("accepted %q", snippet)
		}
	}
	if RepoConfigDenied(base + "[core]\n\tfilemode = true\n") {
		t.Fatal("filemode denied")
	}
	if RepoConfigDenied(base + "[diff \"evil\"]\n\ttextconv = /tmp/mark\n") {
		t.Fatal("textconv denied")
	}
	if RepoConfigDenied(base + "[remote \"origin\"]\n\turl = https://github.com/acme/widgets.git\n") {
		t.Fatal("remote url denied")
	}
}
