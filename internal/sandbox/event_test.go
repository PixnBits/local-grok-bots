package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
		{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied, Owner: "other", Repo: "nope"},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied, Owner: "acme", Repo: "widgets"},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "github", Detail: GitHubAllowlistDenied},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_denied", Grant: "git", Detail: "clone"},
		{Kind: "jail_report", Untrusted: true, Reported: "grant_use", Grant: "git", Detail: "clone"},
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
	if len(ev) != 4 || !ev[0].Untrusted || ev[0].Kind != "jail_report" || ev[0].Reported != "grant_denied" || ev[0].Owner != "other" || ev[0].Repo != "nope" || ev[0].Detail != GitHubAllowlistDenied {
		t.Fatalf("parsed %+v", ev)
	}
	if ev[1].Owner != "acme" || ev[1].Repo != "widgets" || ev[2].Grant != "git" || ev[2].Detail != "clone" || ev[2].Kind != "jail_report" {
		t.Fatalf("parsed %+v", ev)
	}
	if ev[3].Grant != "github" || ev[3].Owner != "" || ev[3].Repo != "" || ev[3].Detail != GitHubAllowlistDenied || ev[3].Kind == "grant_denied" {
		t.Fatalf("parsed %+v", ev)
	}
}

func TestParseEventFileCaps(t *testing.T) {
	t.Run("oversize", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "log")
		var b strings.Builder
		b.WriteString("block hello\n")
		b.WriteString(strings.Repeat("x", 70<<10))
		b.WriteString("\nblock PASTCAP\n")
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		got := parseEventFile(path)
		if len(got) == 0 || got[len(got)-1].Kind != "jail_report_truncated" || got[len(got)-1].Untrusted {
			t.Fatalf("events %+v", got)
		}
		for _, ev := range got {
			if ev.Kind == "sandbox_block" || ev.Kind == "grant_use" || ev.Kind == "grant_denied" {
				t.Fatalf("trusted kind %+v", ev)
			}
			if strings.Contains(ev.Detail, "PASTCAP") {
				t.Fatalf("parsed past the cap %+v", ev)
			}
		}
		if got[0].Kind != "jail_report" || got[0].Reported != "sandbox_block" || got[0].Detail != "hello" {
			t.Fatalf("kept %+v", got[0])
		}
	})
	t.Run("too many lines", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "log")
		var lines []string
		for i := 0; i < maxEventLines+6; i++ {
			lines = append(lines, "deny git n"+strconv.Itoa(i))
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := parseEventFile(path)
		if len(got) != maxEventLines+1 {
			t.Fatalf("len %d", len(got))
		}
		last := got[len(got)-1]
		if last.Kind != "jail_report_truncated" || !strings.Contains(last.Detail, "dropped") {
			t.Fatalf("tail %+v", last)
		}
		for _, ev := range got[:maxEventLines] {
			if ev.Kind != "jail_report" || ev.Reported != "grant_denied" || ev.Kind == "grant_denied" {
				t.Fatalf("line %+v", ev)
			}
		}
		if strings.Contains(got[maxEventLines-1].Detail, "n"+strconv.Itoa(maxEventLines)) {
			t.Fatalf("kept the overflow line %+v", got[maxEventLines-1])
		}
		if got[0].Detail != "n0" || got[maxEventLines-1].Detail != "n"+strconv.Itoa(maxEventLines-1) {
			t.Fatalf("span %+v %+v", got[0], got[maxEventLines-1])
		}
	})
	t.Run("long and non-ascii", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "log")
		long := strings.Repeat("A", 400) + "TAIL" + "\xff\x00"
		body := "block " + long + "\nblock héllo\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		got := parseEventFile(path)
		if len(got) != 2 {
			t.Fatalf("events %+v", got)
		}
		if got[0].Kind != "jail_report" || got[0].Reported != "sandbox_block" || len(got[0].Detail) != maxEventDetail || strings.Contains(got[0].Detail, "TAIL") {
			t.Fatalf("long %+v", got[0])
		}
		for i := 0; i < len(got[0].Detail); i++ {
			if got[0].Detail[i] < 0x20 || got[0].Detail[i] > 0x7e {
				t.Fatalf("non-ascii in long detail %q", got[0].Detail)
			}
		}
		if got[1].Detail != "hllo" || strings.Contains(got[1].Detail, "é") {
			t.Fatalf("non-ascii detail %+v", got[1])
		}
	})
}

func TestEventsHostDirSwap(t *testing.T) {
	ws := t.TempDir()
	p, err := prepare(context.Background(), Request{Workspace: ws, Command: "true"}, ws)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.close)
	if err := os.WriteFile(p.events, []byte("block original-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const marker = "HOST-FORGED-MARKER"
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "log"), []byte("block "+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eventsDir := filepath.Join(p.dir, "rw", "events")
	away := filepath.Join(p.dir, "rw", "events-away")
	if err := os.Rename(eventsDir, away); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(host, eventsDir); err != nil {
		t.Fatal(err)
	}
	got := readPreparedEvents(p)
	sawOriginal := false
	sawUnavailable := false
	for _, ev := range got {
		if strings.Contains(ev.Detail, marker) || strings.Contains(ev.Notice, marker) || strings.Contains(ev.Host, marker) {
			t.Fatalf("host log was read: %+v", got)
		}
		if ev.Detail == "original-line" {
			sawOriginal = true
		}
		if ev.Kind == "jail_report_truncated" && ev.Detail == "events unavailable" && !ev.Untrusted {
			sawUnavailable = true
		}
	}
	if runtime.GOOS == "linux" {
		if !sawOriginal || sawUnavailable {
			t.Fatalf("linux fd lost the original directory: %+v", got)
		}
		return
	}
	if !sawUnavailable && !sawOriginal {
		t.Fatalf("events %+v", got)
	}
	if sawOriginal && sawUnavailable {
		t.Fatalf("both original and unavailable: %+v", got)
	}
}

func TestEventsMissingAndSymlinkLog(t *testing.T) {
	assertUnavailable := func(t *testing.T, got []Event) {
		t.Helper()
		if len(got) != 1 || got[0].Kind != "jail_report_truncated" || got[0].Untrusted || got[0].Detail != "events unavailable" {
			t.Fatalf("events %+v", got)
		}
	}
	t.Run("missing", func(t *testing.T) {
		ws := t.TempDir()
		p, err := prepare(context.Background(), Request{Workspace: ws, Command: "true"}, ws)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.close)
		if err := os.Remove(p.events); err != nil {
			t.Fatal(err)
		}
		assertUnavailable(t, readPreparedEvents(p))
	})
	t.Run("symlink", func(t *testing.T) {
		ws := t.TempDir()
		p, err := prepare(context.Background(), Request{Workspace: ws, Command: "true"}, ws)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.close)
		other := filepath.Join(t.TempDir(), "other")
		if err := os.WriteFile(other, []byte("block SYMLINK-TARGET-MARKER\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p.events); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, p.events); err != nil {
			t.Fatal(err)
		}
		got := readPreparedEvents(p)
		assertUnavailable(t, got)
		for _, ev := range got {
			if strings.Contains(ev.Detail, "SYMLINK-TARGET-MARKER") {
				t.Fatalf("followed the log symlink: %+v", got)
			}
		}
	})
}
