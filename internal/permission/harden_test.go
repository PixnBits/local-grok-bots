package permission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnquotedExpansionRefused(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.txt")
	mustFile(t, ws, "a*b")
	for _, cmd := range []string{
		"cat -- *.txt",
		"cat -- file?.txt",
		"cat -- file[a].txt",
		"cat -- {a,b}",
		"ls -- *.txt",
		"echo {a,b}",
	} {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow {
			t.Fatalf("%q auto-allowed: %+v", cmd, got)
		}
	}
	for _, cmd := range []string{
		"cat -- 'a*b'",
		`cat -- "a*b"`,
		"cat -- 'file[a].txt'",
	} {
		if cmd == "cat -- 'file[a].txt'" {
			mustFile(t, ws, "file[a].txt")
		}
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if !got.AutoAllow {
			t.Fatalf("%q refused: %+v", cmd, got)
		}
	}
}

func TestFileOperandEndOfOptions(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.txt")
	mustFile(t, ws, "-notes")
	if got := ClassifyCall("Bash", map[string]any{"command": "cat notes.txt"}, ws); got.AutoAllow || !strings.Contains(got.Reason, "--") {
		t.Fatalf("bare operand %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -- notes.txt"}, ws); !got.AutoAllow {
		t.Fatalf("ended operand %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -notes"}, ws); got.AutoAllow {
		t.Fatalf("dash operand %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -- -notes"}, ws); !got.AutoAllow {
		t.Fatalf("dash operand after end %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "pwd -notes"}, ws); got.AutoAllow || !strings.Contains(got.Reason, "operand starts with -") {
		t.Fatalf("pwd dash operand %+v", got)
	}
}

func TestReadOnlyOptionAllowlist(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.txt")
	refused := []string{
		"rg --pre run.sh -- notes.txt",
		"rg --pre-glob '*.sh' -- notes.txt",
		"rg --hostname-bin hostname -- notes.txt",
		"rg -z pattern -- notes.txt",
		"rg --search-zip pattern -- notes.txt",
		"file -C -- notes.txt",
		"file --compile -- notes.txt",
		"tail -f -- notes.txt",
		"tail -F -- notes.txt",
		"tail --follow -- notes.txt",
		"grep -f pats -- notes.txt",
		"grep --file=pats -- notes.txt",
	}
	for _, cmd := range refused {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow {
			t.Fatalf("%q auto-allowed: %+v", cmd, got)
		}
	}
	allowed := []string{
		"rg -n pattern -- notes.txt",
		"grep -n pattern -- notes.txt",
		"tail -n 5 -- notes.txt",
		"head -5 -- notes.txt",
		"file -b -- notes.txt",
		"ls -la",
		"wc -l -- notes.txt",
		"pwd",
	}
	for _, cmd := range allowed {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if !got.AutoAllow {
			t.Fatalf("%q refused: %+v", cmd, got)
		}
	}
}

func TestGitNotAutoAllowed(t *testing.T) {
	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	refused := []string{
		"git status",
		"git status -s",
		"git status --short",
		"git status -b",
		"git status --branch",
		"git status --porcelain",
		"git status -sb",
		"git status -bs",
		"git status -- sub",
		"git status -u",
		"git status --untracked-files",
		"git status sub",
		"git log",
		"git log -1",
		"git diff",
		"git diff -- src/a.go",
		"git show HEAD",
		"git rev-parse HEAD",
		"git blame notes.txt",
		"git -C other status",
		"git --git-dir other status",
		"git --git-dir=other status",
		"git --work-tree other status",
		"git --work-tree=other status",
		"git --ext-diff diff",
		"git diff --textconv",
		"git diff --no-index",
		"git --no-index status",
		"git -c core.pager=cat status",
		"git status -c advice.statusUoption=false",
		"git status -- ../outside",
	}
	for _, cmd := range refused {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow {
			t.Fatalf("%q auto-allowed: %+v", cmd, got)
		}
	}
	if _, err := CheckUserRule("allow", "Bash(git log *)", ws); err == nil {
		t.Fatal("git log pattern stored")
	}
	if _, err := CheckUserRule("allow", "Bash(git status*)", ws); err == nil {
		t.Fatal("git status pattern stored")
	}
	if _, err := CheckUserRule("ask", "Bash(git status*)", ws); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkClientNotAutoAllow(t *testing.T) {
	ws := t.TempDir()
	for _, cmd := range []string{"gh pr view 1", "gh pr diff 1", "gh repo view", "gh"} {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow || got.Kind != "network" {
			t.Fatalf("%q %+v", cmd, got)
		}
	}
	if _, err := CheckUserRule("allow", "Bash(gh pr view *)", ws); err == nil {
		t.Fatal("network client pattern stored")
	}
}

func TestSymlinkAndMissingParent(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	mustFile(t, outside, "secret")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(ws, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustFile(t, filepath.Join(ws, "keep"), "a")
	if err := os.Symlink(filepath.Join("keep", "a"), filepath.Join(ws, "inside")); err != nil {
		t.Fatal(err)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -- link"}, ws); got.AutoAllow || !strings.Contains(got.Reason, "resolves outside") {
		t.Fatalf("symlink %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -- inside"}, ws); !got.AutoAllow {
		t.Fatalf("inside symlink %+v", got)
	}
	if got := ClassifyCall("Bash", map[string]any{"command": "cat -- missing/file"}, ws); got.AutoAllow || !strings.Contains(got.Reason, "parent is missing") {
		t.Fatalf("missing parent %+v", got)
	}
	if got := ClassifyCall("Read", map[string]any{"file_path": "link"}, ws); got.AutoAllow {
		t.Fatalf("read symlink %+v", got)
	}
	if got := ClassifyCall("Read", map[string]any{"file_path": "missing/file"}, ws); got.AutoAllow || !strings.Contains(got.Reason, "parent is missing") {
		t.Fatalf("read missing parent %+v", got)
	}
}

func TestGlobAndGrepPathFields(t *testing.T) {
	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok := []struct {
		tool string
		args map[string]any
	}{
		{"Glob", map[string]any{"pattern": "src/**/*.go"}},
		{"Glob", map[string]any{"pattern": "*.go"}},
		{"Glob", map[string]any{"pattern": "**", "path": "src"}},
		{"Glob", map[string]any{"pattern": "*.go", "file_path": "src"}},
		{"Grep", map[string]any{"pattern": "a..b", "path": "src", "glob": "*.go"}},
		{"Grep", map[string]any{"pattern": "TODO"}},
	}
	for _, tc := range ok {
		got := ClassifyCall(tc.tool, tc.args, ws)
		if !got.AutoAllow {
			t.Fatalf("%s %+v refused: %+v", tc.tool, tc.args, got)
		}
	}
	bad := []struct {
		tool string
		args map[string]any
	}{
		{"Glob", map[string]any{"pattern": "/tmp/tree/**"}},
		{"Glob", map[string]any{"pattern": "../x"}},
		{"Glob", map[string]any{"pattern": "~/x"}},
		{"Glob", map[string]any{"pattern": "src/../../etc"}},
		{"Glob", map[string]any{"pattern": "**", "path": "src/../../.."}},
		{"Glob", map[string]any{"pattern": "**", "file_path": "src/../../.."}},
		{"Glob", map[string]any{"pattern": "*.go", "path": "src", "file_path": "../outside"}},
		{"Glob", map[string]any{"pattern": "**", "filePath": "~/x"}},
		{"Grep", map[string]any{"pattern": "TODO", "path": "/tmp/tree"}},
		{"Grep", map[string]any{"pattern": "TODO", "glob": "/tmp/tree/*"}},
		{"Grep", map[string]any{"pattern": "TODO", "glob": "../*.go"}},
		{"Grep", map[string]any{"pattern": "TODO", "path": "~/x"}},
		{"Grep", map[string]any{"pattern": "TODO", "path": "missing/file"}},
	}
	for _, tc := range bad {
		got := ClassifyCall(tc.tool, tc.args, ws)
		if got.AutoAllow {
			t.Fatalf("%s %+v auto-allowed: %+v", tc.tool, tc.args, got)
		}
	}
}

func TestGlobPrefixOutside(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(ws, "src", "out")); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{
		{"pattern": "link/**"},
		{"pattern": "link*"},
		{"pattern": "src/out/**/*.go"},
		{"pattern": "**", "path": "link"},
		{"pattern": "src/**", "file_path": "link"},
	} {
		got := ClassifyCall("Glob", args, ws)
		if got.AutoAllow {
			t.Fatalf("%+v auto-allowed: %+v", args, got)
		}
	}
	if got := ClassifyCall("Glob", map[string]any{"pattern": "src/**/*.go"}, ws); !got.AutoAllow {
		t.Fatalf("inside prefix refused: %+v", got)
	}
}

func TestFindExpressionAllowlist(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.txt")
	allowed := []string{
		"find -- . -name foo",
		"find -- . -type f -print",
		"find -- . ( -name foo )",
		"find -P -- . -name foo",
	}
	for _, cmd := range allowed {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if !got.AutoAllow {
			t.Fatalf("%q refused: %+v", cmd, got)
		}
	}
	refused := []string{
		"find -L -- .",
		"find -H -- .",
		"find -- . -follow",
		"find -- . -name foo -follow",
		"find -- . -delete",
		"find -- . -exec rm x",
		"find -- . -execdir rm x",
		"find -- . -ok rm x",
		"find -- . -fprint out.txt",
		"find -- . -fprintf out.txt p",
		"find -- . -fls out.txt",
		"find -- . -fprint0 out.txt",
		"find -- . -name foo -printf p",
		"find -- . -name foo -ls",
	}
	for _, cmd := range refused {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow {
			t.Fatalf("%q auto-allowed: %+v", cmd, got)
		}
	}
}

func TestNonPrintableBeforeSplit(t *testing.T) {
	ws := t.TempDir()
	for _, cmd := range []string{
		"git status\x00",
		"git\x00status",
		"git status\t",
		"git status\x7f",
		"git status\x80",
		"cat -- 'notes\n.txt'",
	} {
		got := ClassifyCall("Bash", map[string]any{"command": cmd}, ws)
		if got.AutoAllow || !strings.Contains(got.Reason, "non-printable") {
			t.Fatalf("%q %+v", cmd, got)
		}
	}
}

func TestPrefixMatcherSuffixMeta(t *testing.T) {
	if !ruleMatches("Bash(git status*)", "Bash", "git status -sb") {
		t.Fatal("clean suffix")
	}
	for _, cmd := range []string{
		"git status; rm x",
		"git status | cat",
		"git status && true",
		"git status || true",
		"git status `id`",
		"git status $(id)",
		"git status (x)",
		"git status > out",
		"git status < in",
		"git status\nrm",
		"git status\n",
	} {
		if ruleMatches("Bash(git status*)", "Bash", cmd) {
			t.Fatalf("prefix matched %q", cmd)
		}
	}
	if !ruleMatches("Bash(*push*)", "Bash", "git push; rm x") {
		t.Fatal("middle glob stopped matching")
	}
}

func mustFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
