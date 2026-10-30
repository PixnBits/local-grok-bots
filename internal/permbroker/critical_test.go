package permbroker

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

type critSet struct {
	data     string
	settings string
	paths    []string
}

func criticalEngine(t *testing.T) (*Engine, critSet) {
	t.Helper()
	e := testEngine(t)
	data := t.TempDir()
	hook := filepath.Join(data, "bin", "lgb-permhook")
	settings := filepath.Join(data, "cli", "bot", "claude-settings.json")
	paths := BrokerCriticalPaths(data, hook, settings, filepath.Dir(settings))
	if len(paths) != 4 {
		t.Fatalf("critical set %v", paths)
	}
	e.SetCriticalPaths(paths)
	return e, critSet{data: data, settings: settings, paths: paths}
}

func TestGolden_CriticalPathsApproveOnceRetry(t *testing.T) {
	e, _ := criticalEngine(t)
	ctx := context.Background()
	for _, cmd := range []string{"git status", "touch canary_a"} {
		req := bashReq("bot", "sess", "task", "/work", cmd)
		first := e.Evaluate(ctx, req)
		if first.Level == LevelCritical || first.Verdict == VerdictAllow || first.PendingID == "" {
			t.Fatalf("%s %+v", cmd, first)
		}
		if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
			t.Fatalf("%s approve %v", cmd, err)
		}
		allowed := e.Evaluate(ctx, req)
		if allowed.Verdict != VerdictAllow {
			t.Fatalf("%s retry %+v", cmd, allowed)
		}
		second := e.Evaluate(ctx, req)
		if second.Verdict == VerdictAllow || second.PendingID == "" {
			t.Fatalf("%s second %+v", cmd, second)
		}
	}
}

func TestGolden_CriticalPathsGrantAndRule(t *testing.T) {
	e, _ := criticalEngine(t)
	ctx := context.Background()
	status := bashReq("bot", "sess", "task", "/work", "git status")
	asked := e.Evaluate(ctx, status)
	if asked.Level == LevelCritical || asked.PendingID == "" {
		t.Fatalf("ask %+v", asked)
	}
	if err := e.Decide(asked.PendingID, "approve", ScopeTask); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, status); d.Verdict != VerdictAllow || !strings.Contains(d.Reason, "task") {
		t.Fatalf("grant %+v", d)
	}
	diff := bashReq("bot", "sess", "task", "/work", "git diff")
	if d := e.Evaluate(ctx, diff); d.Level == LevelCritical || d.Verdict == VerdictAllow {
		t.Fatalf("diff before rule %+v", d)
	}
	if _, err := e.SaveRule(Rule{
		Effect: EffectAllow, Argv: []string{"git", "diff"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
	}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, diff); d.Verdict != VerdictAllow || !strings.Contains(d.Reason, "rule") {
		t.Fatalf("rule %+v", d)
	}
}

func TestGolden_CriticalPathsStillCritical(t *testing.T) {
	e, set := criticalEngine(t)
	ctx := context.Background()
	benign := bashReq("bot", "ctrl", "task", "/work", "git status")
	first := e.Evaluate(ctx, benign)
	if first.Level == LevelCritical || first.PendingID == "" {
		t.Fatalf("benign %+v", first)
	}
	if err := e.Decide(first.PendingID, "approve", ScopeOnce); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(ctx, benign); d.Verdict != VerdictAllow {
		t.Fatalf("benign retry %+v", d)
	}
	if d := e.Evaluate(ctx, benign); d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("benign second %+v", d)
	}

	abs := filepath.Join(set.data, "permbroker", "state")
	if !underRoot(abs, filepath.Join(set.data, "permbroker")) {
		t.Fatalf("fixture %s", abs)
	}
	cases := []struct {
		name string
		req  Request
		argv []string
		save bool
	}{
		{
			name: "absolute",
			req:  bashReq("bot", "sess", "task", "/work", "git status "+abs),
			argv: []string{"git", "status", abs},
			save: true,
		},
		{
			name: "relative",
			req:  bashReq("bot", "sess", "task", set.data, "git status permbroker/notes"),
		},
		{
			name: "flag",
			req:  bashReq("bot", "sess", "task", "/work", "git status --flag="+set.settings),
			argv: []string{"git", "status", "--flag=" + set.settings},
			save: true,
		},
	}
	for _, tc := range cases {
		if tc.save {
			if _, err := e.SaveRule(Rule{
				Effect: EffectAllow, Argv: tc.argv, Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
			}); err != ErrScope {
				t.Fatalf("%s rule %v", tc.name, err)
			}
		}
		d := e.Evaluate(ctx, tc.req)
		if d.Level != LevelCritical || d.Verdict == VerdictAllow || d.PendingID == "" {
			t.Fatalf("%s %+v", tc.name, d)
		}
		for _, scope := range []string{ScopeTask, ScopeBot, ScopeGlobal} {
			if err := e.Decide(d.PendingID, "approve", scope); err != ErrScope {
				t.Fatalf("%s scope %s %v", tc.name, scope, err)
			}
		}
		if err := e.Decide(d.PendingID, "approve", ScopeOnce); err != nil {
			t.Fatalf("%s once %v", tc.name, err)
		}
		again := e.Evaluate(ctx, tc.req)
		if again.Verdict == VerdictAllow || again.Level != LevelCritical {
			t.Fatalf("%s consumed %+v", tc.name, again)
		}
	}
	e.SetCriticalPaths(nil)
	for _, tc := range cases {
		allowed := e.Evaluate(ctx, tc.req)
		if allowed.Verdict != VerdictAllow {
			t.Fatalf("%s token %+v", tc.name, allowed)
		}
		if d := e.Evaluate(ctx, tc.req); d.Verdict == VerdictAllow {
			t.Fatalf("%s token reused %+v", tc.name, d)
		}
	}
}
