package permbroker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGolden_PatternSyntaxCISO(t *testing.T) {
	cases := []struct {
		pattern string
		reason  string
	}{
		{pattern: "git show * --stat"},
		{pattern: "git diff * --stat"},
		{pattern: "find * -print"},
		{pattern: "git * status"},
		{pattern: "git log **", reason: ReasonTrailingWildcard},
		{pattern: "git diff *", reason: ReasonTrailingWildcard},
		{pattern: "bash *", reason: ReasonTrailingWildcard},
		{pattern: "* status", reason: ReasonStarFirst},
		{pattern: "git diff*", reason: ReasonStarInWord},
		{pattern: "git *bar status", reason: ReasonStarInWord},
		{pattern: "sh -c * true", reason: ReasonWrapperCommand},
		{pattern: "find * -exec", reason: ReasonWrapperCommand},
		{pattern: "python * script.py", reason: ReasonWrapperCommand},
		{pattern: "git diff -*", reason: ReasonFlagPosition},
		{pattern: "git diff && git status", reason: ReasonOperator},
		{pattern: "git show ? --stat", reason: ReasonOperator},
		{pattern: "", reason: ReasonOperator},
		{pattern: "   ", reason: ReasonOperator},
	}
	for _, tc := range cases {
		err := ValidatePattern(tc.pattern)
		if tc.reason == "" {
			if err != nil {
				t.Fatalf("valid %q: %v", tc.pattern, err)
			}
			continue
		}
		var pe *PatternError
		if !errors.As(err, &pe) || pe.Reason != tc.reason {
			t.Fatalf("%q reason %q err %v", tc.pattern, tc.reason, err)
		}
	}
}

func TestGolden_PatternMatchOneTokenNoFlag(t *testing.T) {
	pat := "git diff * --stat"
	if !patternMatch(pat, []string{"git", "diff", "HEAD", "--stat"}) {
		t.Fatal("one token")
	}
	if patternMatch(pat, []string{"git", "diff", "-p", "--stat"}) {
		t.Fatal("flag")
	}
	if patternMatch(pat, []string{"git", "diff", "a/b", "--stat"}) {
		t.Fatal("slash")
	}
	if patternMatch(pat, []string{"git", "diff", `a\b`, "--stat"}) {
		t.Fatal("backslash")
	}
	if patternMatch(pat, []string{"git", "diff", "HEAD", "--stat", "extra"}) {
		t.Fatal("extra token")
	}
	if patternMatch(pat, []string{"/usr/bin/git", "diff", "HEAD", "--stat"}) {
		t.Fatal("basename")
	}
	if patternMatch("git diff *", []string{"git", "diff", "HEAD"}) {
		t.Fatal("trailing wildcard matched")
	}

	e := testEngine(t)
	e.mu.Lock()
	e.rules.Rules = []Rule{
		{ID: "bad", Effect: EffectAllow, Kind: "pattern", Pattern: "git diff*", Tool: ToolShell, Scope: ScopeBot, BotID: "bot"},
		{ID: "pat", Effect: EffectAllow, Kind: "pattern", Pattern: pat, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"},
		{ID: "ex", Effect: EffectAllow, Kind: "exact", Argv: []string{"git", "diff", "HEAD", "--stat"}, Tool: ToolShell, Scope: ScopeBot, BotID: "bot"},
	}
	e.mu.Unlock()
	ctx := context.Background()
	plain := e.Evaluate(ctx, shellReq("Bash", "git diff"))
	if plain.Verdict != VerdictAllow || plain.RuleID != "bad" {
		t.Fatalf("invalid pattern was not legacy %+v", plain)
	}
	wide := e.Evaluate(ctx, shellReq("Bash", "git diff --stat"))
	if wide.Verdict == VerdictAllow {
		t.Fatalf("legacy allow grew %+v", wide)
	}
	exact := e.Evaluate(ctx, shellReq("Bash", "git diff HEAD --stat"))
	if exact.Verdict != VerdictAllow || exact.RuleID != "ex" {
		t.Fatalf("exact did not beat pattern %+v", exact)
	}
	e.mu.Lock()
	e.rules.Rules = append(e.rules.Rules, Rule{
		ID: "ask", Effect: EffectAsk, Kind: "pattern", Pattern: pat,
		Tool: ToolShell, Scope: ScopeBot, BotID: "bot",
	})
	e.mu.Unlock()
	asked := e.Evaluate(ctx, shellReq("Bash", "git diff HEAD --stat"))
	if asked.Verdict == VerdictAllow || asked.PendingID == "" {
		t.Fatalf("pattern ask lost to exact allow %+v", asked)
	}
}

func TestGolden_MigrationOnlyNarrows(t *testing.T) {
	e := testEngine(t)
	rules := []LegacyRule{
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff * --stat)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff*)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git  diff * --stat)"},
		{BotID: "bot", Effect: EffectDeny, Text: "Bash(git log **)"},
	}
	if err := e.MigrateLegacy(rules); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(e.dir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc rulesFile
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	kindOf := map[string]string{}
	for _, rule := range doc.Rules {
		kindOf[rule.Text] = rule.Kind
	}
	if kindOf["Bash(git diff * --stat)"] != "pattern" {
		t.Fatalf("converting glob stayed %q\n%s", kindOf["Bash(git diff * --stat)"], body)
	}
	for _, text := range []string{"Bash(git diff*)", "Bash(git  diff * --stat)", "Bash(git log **)"} {
		if kindOf[text] != "legacy" {
			t.Fatalf("%s kind %q", text, kindOf[text])
		}
	}
	words := strings.Fields("git diff * --stat")
	if !patternNarrows("git diff * --stat", words) {
		t.Fatal("subset proof failed")
	}
	for _, w := range patternWitnesses {
		argv := []string{"git", "diff", w, "--stat"}
		if !patternMatch("git diff * --stat", argv) {
			continue
		}
		ok, err := filepath.Match("git diff * --stat", strings.Join(argv, " "))
		if err != nil || !ok {
			t.Fatalf("pattern wider than glob for %q", w)
		}
	}
	if patternMatch("git diff * --stat", []string{"git", "diff", "a/b", "--stat"}) {
		t.Fatal("slash token matched")
	}
	if patternMatch("git diff * --stat", []string{"git", "diff", "-n", "--stat"}) {
		t.Fatal("flag token matched")
	}
	var patternID string
	for _, rule := range e.ListRules() {
		if rule.Kind == "pattern" {
			patternID = rule.ID
		}
	}
	if patternID == "" {
		t.Fatal("pattern row missing")
	}
	if _, err := e.ConfirmRule(patternID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ws := t.TempDir()
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git diff HEAD --stat")); d.Verdict != VerdictAllow {
		t.Fatalf("narrow %+v", d)
	}
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git diff src/main.go --stat")); d.Verdict == VerdictAllow {
		t.Fatalf("path %+v", d)
	}
	if d := e.Evaluate(ctx, bashReq("bot", "sess", "task", ws, "git diff --stat")); d.Verdict == VerdictAllow {
		t.Fatalf("legacy grew %+v", d)
	}
}

func TestGolden_LegacyAllowNeverWrapperCriticalCompound(t *testing.T) {
	e := testEngine(t)
	rules := []LegacyRule{
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(sh -c *)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(gh auth *)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff*)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(python *)"},
	}
	if err := e.MigrateLegacy(rules); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, cmd := range []string{"sh -c true", "python -c pass", "gh auth token", "git diff && true"} {
		if d := e.Evaluate(ctx, shellReq("Bash", cmd)); d.Verdict == VerdictAllow {
			t.Fatalf("%s %+v", cmd, d)
		}
	}
	sh := &Rule{Effect: EffectAllow, Kind: "legacy", Pattern: "sh -c *", Tool: ToolShell}
	if ruleHit(sh, inspected{Eligible: true, Argv: []string{"sh", "-c", "true"}, Raw: "sh -c true", Level: LevelLow}, false) {
		t.Fatal("wrapper allow")
	}
	gh := &Rule{Effect: EffectAllow, Kind: "legacy", Pattern: "gh auth *", Tool: ToolShell}
	if ruleHit(gh, inspected{Eligible: true, Argv: []string{"gh", "auth", "token"}, Raw: "gh auth token", Level: LevelCritical}, false) {
		t.Fatal("critical allow")
	}
	diff := &Rule{Effect: EffectAllow, Kind: "legacy", Pattern: "git diff*", Tool: ToolShell}
	if ruleHit(diff, inspected{Eligible: true, Compound: true, Argv: []string{"git", "diff"}, Raw: "git diff", Level: LevelLow}, false) {
		t.Fatal("compound allow")
	}
	exact := &Rule{Effect: EffectAllow, Kind: "exact", Argv: []string{"git", "status"}, Tool: ToolShell}
	if ruleHit(exact, inspected{Eligible: true, Compound: true, Argv: []string{"git", "status"}, Level: LevelLow}, false) {
		t.Fatal("exact compound allow")
	}
	deny := &Rule{Effect: EffectDeny, Kind: "legacy", Pattern: "git log **", Tool: ToolShell}
	if !ruleHit(deny, inspected{Argv: []string{"git", "log", "--oneline"}, Raw: "git log --oneline", Level: LevelLow}, true) {
		t.Fatal("deny legacy stopped applying")
	}
}

func TestGolden_CompoundTaskGrantConditions(t *testing.T) {
	e := testEngine(t)
	if err := e.MigrateLegacy([]LegacyRule{
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git status)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff*)"},
		{BotID: "bot", Effect: EffectAllow, Text: "Bash(git diff * --stat)"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	comp := shellReq("Bash", "git status && git diff")
	if d := e.Evaluate(ctx, comp); d.Verdict == VerdictAllow || !d.Compound {
		t.Fatalf("rules covered compound %+v", d)
	}
	narrow := shellReq("Bash", "git diff HEAD --stat && git status")
	if d := e.Evaluate(ctx, narrow); d.Verdict == VerdictAllow {
		t.Fatalf("pattern covered compound %+v", d)
	}
	exact := &Rule{Effect: EffectAllow, Kind: "exact", Argv: []string{"git", "status"}, Tool: ToolShell}
	if ruleHit(exact, inspected{Eligible: true, Compound: true, Argv: []string{"git", "status"}, Level: LevelLow}, false) {
		t.Fatal("exact allow matched a compound")
	}
	grantArgv(e, []string{"git", "status"})
	if d := e.Evaluate(ctx, comp); d.Verdict == VerdictAllow {
		t.Fatalf("partial grant %+v", d)
	}
	grantArgv(e, []string{"git", "diff"})
	full := e.Evaluate(ctx, comp)
	if full.Verdict != VerdictAllow || full.RuleID != "" || !strings.Contains(full.Reason, "task") {
		t.Fatalf("full grant %+v", full)
	}
	hard := shellReq("Bash", "git status && echo hi")
	grantArgv(e, []string{"echo", "hi"})
	if d := e.Evaluate(ctx, hard); d.Verdict == VerdictAllow {
		t.Fatalf("hard part %+v", d)
	}
}
