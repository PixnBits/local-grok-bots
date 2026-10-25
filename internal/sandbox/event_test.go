package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowlistEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log")
	body := strings.Join([]string{
		"deny github allowlist https://github.com/Other/Nope.git",
		"deny github allowlist git@github.com:AcMe/WiDgEtS.git",
		"deny github allowlist https://evil.example/nope",
		"deny github allowlist ssh://github.com/acme/widgets.git",
		"deny git clone",
		"use git clone",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := parseEventFile(path)
	want := []Event{
		{Kind: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied, Owner: "other", Repo: "nope"},
		{Kind: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied, Owner: "acme", Repo: "widgets"},
		{Kind: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied},
		{Kind: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied},
		{Kind: "grant_denied", Grant: "git", Detail: "clone"},
		{Kind: "grant_use", Grant: "git", Detail: "clone"},
	}
	if len(got) != len(want) {
		t.Fatalf("events %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestWrapperAllowlistLineStaysOneLine(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Repos: []string{"acme/widgets"}, Bridge: true})
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events")
	if strings.ContainsAny(logPath, " \t\n'\"\\$`;") {
		t.Fatalf("temp path is not safe to splice: %s", logPath)
	}
	script = strings.ReplaceAll(script, "log=/lgb/events/log", "log="+logPath)
	path := filepath.Join(dir, "git")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(path, args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("%v was allowed: %s", args, out)
		}
		if !strings.Contains(string(out), "not allowlisted") {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	run("clone", "https://github.com/Other/Nope.git", "dest")
	run("clone", "git@github.com:Acme/Widgets.GIT", "dest")
	run("clone", "https://github.com/acme/widgets.git\nuse git pwned", "dest")
	run("fetch", "https://evil.example/nope")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "pwned") {
		t.Fatalf("newline url was written to the event log:\n%s", text)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	want := []string{
		"deny github allowlist https://github.com/Other/Nope.git",
		"deny github allowlist git@github.com:Acme/Widgets.GIT",
		"deny git clone",
		"deny github allowlist https://evil.example/nope",
	}
	if len(lines) != len(want) {
		t.Fatalf("lines:\n%s", text)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d: got %q want %q", i, lines[i], want[i])
		}
	}
	ev := parseEventFile(logPath)
	if len(ev) != 4 || ev[0].Owner != "other" || ev[0].Repo != "nope" || ev[0].Detail != GitHubAllowlistDenied {
		t.Fatalf("parsed %+v", ev)
	}
	if ev[1].Owner != "acme" || ev[1].Repo != "widgets" || ev[2].Grant != "git" || ev[2].Detail != "clone" {
		t.Fatalf("parsed %+v", ev)
	}
	if ev[3].Grant != "github" || ev[3].Owner != "" || ev[3].Repo != "" || ev[3].Detail != GitHubAllowlistDenied {
		t.Fatalf("parsed %+v", ev)
	}
}
