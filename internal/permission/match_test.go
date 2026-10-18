package permission

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestPathRuleMatchesEquivalentForms(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "a.txt")
	if err := os.MkdirAll(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustFile(t, filepath.Join(ws, "src"), "main.go")
	absA := filepath.Join(ws, "a.txt")
	absSrc := filepath.Join(ws, "src", "main.go")

	req := func(tool string, args map[string]any) Request {
		return Request{Tool: tool, Args: args, Workspace: ws}
	}
	mustMatch := func(rule string, r Request) {
		t.Helper()
		if !ruleMatchesCall(rule, r, argText(r.Args)) {
			t.Fatalf("%s did not match %+v", rule, r.Args)
		}
	}
	mustMiss := func(rule string, r Request) {
		t.Helper()
		if ruleMatchesCall(rule, r, argText(r.Args)) {
			t.Fatalf("%s matched %+v", rule, r.Args)
		}
	}

	mustMatch("Read(./**)", req("Read", map[string]any{"file_path": "a.txt"}))
	mustMatch("Read(./**)", req("Read", map[string]any{"file_path": "./a.txt"}))
	mustMatch("Read(./**)", req("Read", map[string]any{"file_path": absA}))
	mustMatch("Read(./src/**)", req("Read", map[string]any{"file_path": "src/main.go"}))
	mustMatch("Read(./src/**)", req("Read", map[string]any{"file_path": "./src/main.go"}))
	mustMatch("Read(./src/**)", req("Read", map[string]any{"file_path": absSrc}))
	mustMiss("Read(./**)", req("Read", map[string]any{"file_path": "/etc/passwd"}))
	mustMiss("Read(./src/**)", req("Read", map[string]any{"file_path": "a.txt"}))

	mustMatch("Grep(./**)", req("Grep", map[string]any{"pattern": "todo", "path": "."}))
	mustMatch("Grep(./**)", req("Grep", map[string]any{"pattern": "todo"}))
	mustMatch("Grep(./**)", req("Grep", map[string]any{"pattern": "todo", "path": absA}))
	mustMiss("Grep(./**)", req("Grep", map[string]any{"pattern": "todo", "path": "/etc"}))

	mustMatch("Glob(./**)", req("Glob", map[string]any{"pattern": "*.txt"}))
	mustMatch("Glob(./**)", req("Glob", map[string]any{"pattern": "*.txt", "path": "."}))
	mustMatch("Glob(./src/**)", req("Glob", map[string]any{"pattern": "*.go", "path": "src"}))
	mustMiss("Glob(./**)", req("Glob", map[string]any{"pattern": "*.txt", "path": "/etc"}))

	mustMatch("Bash(find *)", req("Bash", map[string]any{"command": "find -- a.txt"}))
	mustMatch("Bash(find *)", req("Bash", map[string]any{"command": "find a.txt"}))
	mustMatch("Bash(cat *)", req("Bash", map[string]any{"command": "cat -- a.txt"}))
	mustMatch("Bash(cat *)", req("Bash", map[string]any{"command": "cat a.txt"}))
}

func TestSuggestShapesMatchRealisticCalls(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "a.txt")
	if err := os.MkdirAll(filepath.Join(ws, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustFile(t, filepath.Join(ws, "src"), "main.go")
	absA := filepath.Join(ws, "a.txt")

	type call struct {
		tool string
		args map[string]any
	}
	groups := []struct {
		name  string
		want  string
		calls []call
	}{
		{
			name: "read",
			want: "Read(./**)",
			calls: []call{
				{"Read", map[string]any{"file_path": absA}},
				{"Read", map[string]any{"file_path": "a.txt"}},
				{"Read", map[string]any{"file_path": "./a.txt"}},
			},
		},
		{
			name: "grep",
			want: "Grep(./**)",
			calls: []call{
				{"Grep", map[string]any{"pattern": "todo", "path": "."}},
				{"Grep", map[string]any{"pattern": "todo"}},
				{"Grep", map[string]any{"pattern": "todo", "path": "a.txt"}},
			},
		},
		{
			name: "glob",
			want: "Glob(./**)",
			calls: []call{
				{"Glob", map[string]any{"pattern": "*.txt"}},
				{"Glob", map[string]any{"pattern": "*.txt", "path": "."}},
				{"Glob", map[string]any{"pattern": "a.txt"}},
			},
		},
		{
			name: "find",
			want: "Bash(find *)",
			calls: []call{
				{"Bash", map[string]any{"command": "find -- a.txt"}},
				{"Bash", map[string]any{"command": "find -- ."}},
				{"Bash", map[string]any{"command": "find -- src"}},
			},
		},
		{
			name: "cat",
			want: "Bash(cat *)",
			calls: []call{
				{"Bash", map[string]any{"command": "cat -- a.txt"}},
				{"Bash", map[string]any{"command": "cat -- ./a.txt"}},
				{"Bash", map[string]any{"command": "cat -- src/main.go"}},
			},
		},
	}

	for _, g := range groups {
		t.Run(g.name, func(t *testing.T) {
			var samples []Sample
			for _, c := range g.calls {
				samples = append(samples, Sample{Tool: c.tool, Args: c.args})
			}
			cards := Suggest(samples, ws)
			if len(cards) != 1 || cards[0].Pattern != g.want {
				t.Fatalf("suggest %+v", cards)
			}
			if _, err := CheckUserRule("allow", cards[0].Pattern, ws); err != nil && !cards[0].Refused {
				t.Fatalf("suggested %s is not storable: %v", cards[0].Pattern, err)
			}
			for _, c := range g.calls {
				req := Request{Tool: c.tool, Args: c.args, Workspace: ws}
				if !ruleMatchesCall(cards[0].Pattern, req, argText(c.args)) {
					t.Fatalf("suggested %s missed %+v", cards[0].Pattern, c.args)
				}
			}
		})
	}
}

func TestUserAllowMatchesNormalizedRead(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "a.txt")
	b := New(Options{})
	pol := policy.Permission{UIPrompts: false}
	rules := []UserRule{{ID: "r", Effect: "allow", Pattern: "Read(./**)"}}
	eval := func(args map[string]any) Outcome {
		t.Helper()
		return b.Evaluate(t.Context(), pol, Request{
			ID: "1", RunID: "run", BotID: "bot", Tool: "Read", Workspace: ws,
			UserRules: rules, Args: args,
		})
	}
	for _, args := range []map[string]any{
		{"file_path": "a.txt"},
		{"file_path": "./a.txt"},
		{"file_path": filepath.Join(ws, "a.txt")},
	} {
		out := eval(args)
		if out.Decision != Allow || out.Source != "user" || out.Rule != "Read(./**)" {
			t.Fatalf("%+v -> %+v", args, out)
		}
	}
	out := eval(map[string]any{"file_path": "/etc/passwd"})
	if out.Decision == Allow || out.Source == "user" {
		t.Fatalf("outside path auto-allowed: %+v", out)
	}
}

func TestBashFindOperandStillNeedsEndOfOptions(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "a.txt")
	b := New(Options{})
	pol := policy.Permission{UIPrompts: false}
	rules := []UserRule{{ID: "r", Effect: "allow", Pattern: "Bash(find *)"}}
	ended := b.Evaluate(t.Context(), pol, Request{
		ID: "1", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws,
		UserRules: rules, Args: map[string]any{"command": "find -- a.txt"},
	})
	if ended.Decision != Allow || ended.Source != "user" {
		t.Fatalf("find with -- %+v", ended)
	}
	bare := b.Evaluate(t.Context(), pol, Request{
		ID: "2", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws,
		UserRules: rules, Args: map[string]any{"command": "find a.txt"},
	})
	if bare.Decision == Allow || bare.Source == "user" {
		t.Fatalf("find without -- auto-allowed: %+v", bare)
	}
	if !ruleMatchesCall("Bash(find *)", Request{Tool: "Bash", Args: map[string]any{"command": "find a.txt"}}, "find a.txt") {
		t.Fatal("rule should still match the call text")
	}
}

func TestSessionGrantWebFetchAndNotebook(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.ipynb")
	b := New(Options{UIPresent: func(string) bool { return true }})
	approve := func(id, tool string, args map[string]any) {
		t.Helper()
		done := make(chan Outcome, 1)
		go func() {
			done <- b.Evaluate(t.Context(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second, AllowSessionGrants: true}, Request{
				ID: id, RunID: "run", BotID: "bot", SessionID: "sess", Tool: tool, Workspace: ws, Args: args,
			})
		}()
		waitForPending(t, b, id)
		if err := b.DecideFor("bot", "run", id, AllowSession); err != nil {
			t.Fatal(err)
		}
		out := <-done
		if out.Decision != AllowSession {
			t.Fatalf("approve %+v", out)
		}
	}
	quiet := policy.Permission{UIPrompts: false}
	approve("w1", "WebFetch", map[string]any{"url": "https://host.invalid/a"})
	same := b.Evaluate(t.Context(), quiet, Request{
		RunID: "run-2", BotID: "bot", SessionID: "sess", Tool: "WebFetch", Workspace: ws,
		Args: map[string]any{"url": "https://host.invalid/a"},
	})
	if same.Decision != Allow || same.Source != "ui" {
		t.Fatalf("same url %+v", same)
	}
	other := b.Evaluate(t.Context(), quiet, Request{
		RunID: "run-3", BotID: "bot", SessionID: "sess", Tool: "WebFetch", Workspace: ws,
		Args: map[string]any{"url": "https://host.invalid/b"},
	})
	if other.Decision == Allow || other.Source == "ui" {
		t.Fatalf("other url %+v", other)
	}

	approve("n1", "NotebookEdit", map[string]any{"notebook_path": "notes.ipynb", "cell": 1})
	sameNB := b.Evaluate(t.Context(), quiet, Request{
		RunID: "run-4", BotID: "bot", SessionID: "sess", Tool: "NotebookEdit", Workspace: ws,
		Args: map[string]any{"notebook_path": "./notes.ipynb", "cell": 9},
	})
	if sameNB.Decision != Allow || sameNB.Source != "ui" {
		t.Fatalf("same notebook %+v", sameNB)
	}

	approve("e1", "UnknownTool", map[string]any{"q": "one", "n": 1})
	sameJSON := b.Evaluate(t.Context(), quiet, Request{
		RunID: "run-5", BotID: "bot", SessionID: "sess", Tool: "UnknownTool", Workspace: ws,
		Args: map[string]any{"n": 1, "q": "one"},
	})
	if sameJSON.Decision != Allow || sameJSON.Source != "ui" {
		t.Fatalf("canonical json %+v", sameJSON)
	}
	otherJSON := b.Evaluate(t.Context(), quiet, Request{
		RunID: "run-6", BotID: "bot", SessionID: "sess", Tool: "UnknownTool", Workspace: ws,
		Args: map[string]any{"q": "two", "n": 1},
	})
	if otherJSON.Decision == Allow || otherJSON.Source == "ui" {
		t.Fatalf("other json %+v", otherJSON)
	}
}

func TestPrefixMetaStillBlocksBash(t *testing.T) {
	if ruleMatches("Bash(cat *)", "Bash", "cat -- a.txt; rm x") {
		t.Fatal("composed cat matched")
	}
}

func TestGrepRgAllowPattern(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "notes.txt")
	if _, err := CheckUserRule("allow", "Bash(grep *)", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUserRule("allow", "Bash(rg *)", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUserRule("allow", "Bash(grep -f *)", ws); err == nil {
		t.Fatal("grep -f pattern stored")
	}
	if _, err := CheckUserRule("allow", "Bash(rg --pre *)", ws); err == nil {
		t.Fatal("rg --pre pattern stored")
	}
	b := New(Options{})
	pol := policy.Permission{UIPrompts: false}
	eval := func(pattern, cmd string) Outcome {
		t.Helper()
		return b.Evaluate(t.Context(), pol, Request{
			ID: "1", RunID: "run", BotID: "bot", Tool: "Bash", Workspace: ws,
			UserRules: []UserRule{{ID: "r", Effect: "allow", Pattern: pattern}},
			Args:      map[string]any{"command": cmd},
		})
	}
	ok := eval("Bash(grep *)", "grep todo -- notes.txt")
	if ok.Decision != Allow || ok.Source != "user" {
		t.Fatalf("safe grep %+v", ok)
	}
	ok = eval("Bash(rg *)", "rg todo -- notes.txt")
	if ok.Decision != Allow || ok.Source != "user" {
		t.Fatalf("safe rg %+v", ok)
	}
	for _, cmd := range []string{
		"grep -f pats -- notes.txt",
		"rg --pre run.sh -- notes.txt",
		"rg --pre-glob '*.sh' -- notes.txt",
		"rg --hostname-bin hostname -- notes.txt",
		"rg -z todo -- notes.txt",
		"rg --search-zip todo -- notes.txt",
	} {
		out := eval("Bash(grep *)", cmd)
		if cmd != "grep -f pats -- notes.txt" {
			out = eval("Bash(rg *)", cmd)
		}
		if out.Decision == Allow || out.Source == "user" {
			t.Fatalf("%q auto-allowed: %+v", cmd, out)
		}
	}
}
