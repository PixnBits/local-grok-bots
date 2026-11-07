package permbroker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCeilingCoversMatrix(t *testing.T) {
	levels := []Level{LevelLow, LevelMedium, LevelHigh, LevelCritical, LevelUnclassified, "", "bogus", "HIGH"}
	ceilings := []Level{LevelLow, LevelMedium, LevelHigh, LevelCritical, "bogus", "", LevelUnclassified, "HIGH"}
	for _, level := range levels {
		for _, ceiling := range ceilings {
			got := ceilingCovers(level, ceiling)
			want := false
			switch level {
			case LevelLow:
				want = ceiling == LevelLow || ceiling == LevelMedium || ceiling == LevelHigh || ceiling == LevelCritical
			case LevelMedium:
				want = ceiling == LevelMedium || ceiling == LevelHigh || ceiling == LevelCritical
			case LevelHigh:
				want = ceiling == LevelHigh || ceiling == LevelCritical
			case LevelCritical:
				want = ceiling == LevelCritical
			}
			if got != want {
				t.Fatalf("ceilingCovers(%q, %q) = %v, want %v", level, ceiling, got, want)
			}
		}
	}
	if _, ok := ceilingRank(LevelUnclassified); ok {
		t.Fatal("unclassified has a rank")
	}
	if _, ok := ceilingRank(""); ok {
		t.Fatal("empty has a rank")
	}
	if _, ok := ceilingRank("HIGH"); ok {
		t.Fatal("HIGH has a rank")
	}
}

func TestCeilingMatchGates(t *testing.T) {
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	req := bashReq(ceilingBot, "sess", "task", "/work", "git status")
	base := inspected{
		Eligible: true, Literal: true, Level: LevelLow,
		Argv: []string{"git", "status"}, Raw: "git status",
	}
	if _, ok := e.ceilingMatch(req, base); !ok {
		t.Fatal("plain low did not match a critical ceiling")
	}
	hard := base
	hard.HardAsk = true
	if _, ok := e.ceilingMatch(req, hard); ok {
		t.Fatal("hard ask matched")
	}
	ineligible := base
	ineligible.Eligible = false
	if _, ok := e.ceilingMatch(req, ineligible); ok {
		t.Fatal("ineligible matched")
	}
	risk := base
	risk.GitRisk = "filter"
	if _, ok := e.ceilingMatch(req, risk); ok {
		t.Fatal("git risk matched")
	}
	reason := base
	reason.GitReason = "baseline drift"
	if _, ok := e.ceilingMatch(req, reason); ok {
		t.Fatal("git reason matched")
	}
	compound := base
	compound.Level = LevelCritical
	compound.Compound = true
	compound.Parts = []Part{
		{Argv: []string{"git", "remote"}, Level: LevelCritical},
		{Argv: []string{"echo", "hi"}, Level: LevelUnclassified},
	}
	if _, ok := e.ceilingMatch(req, compound); ok {
		t.Fatal("unclassified compound part matched")
	}
	known := base
	known.Compound = true
	known.Level = LevelMedium
	known.Eligible = false
	known.Parts = []Part{
		{Argv: []string{"git", "status"}, Level: LevelLow},
		{Argv: []string{"git", "diff"}, Level: LevelLow},
	}
	if _, ok := e.ceilingMatch(req, known); ok {
		t.Fatal("ineligible known compound matched")
	}
	crit := base
	crit.Level = LevelCritical
	crit.HardAsk = true
	crit.Eligible = false
	if ceiling, ok := e.ceilingMatch(req, crit); !ok || ceiling != LevelCritical {
		t.Fatal("critical level did not match a critical ceiling")
	}
	pol := filepath.Join(t.TempDir(), "policy.toml")
	e.SetPolicyPaths(pol)
	touched := base
	touched.Raw = "git status " + pol
	touched.Argv = []string{"git", "status", pol}
	if _, ok := e.ceilingMatch(req, touched); ok {
		t.Fatal("policy path matched at a critical ceiling")
	}
}

func TestAllowCeilingCompoundsAndParse(t *testing.T) {
	ctx := context.Background()
	cmds := []string{
		"git status; git diff",
		"git status && git diff",
		"git status || git diff",
		"git status | git diff",
		"git status\ngit diff",
		"cd /work && git status",
		"git status $(id)",
		"git status `id`",
		"git -c core.fsmonitor=x status",
		"git -c core.pager=less log",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			e := testEngine(t)
			e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelMedium})
			d := e.Evaluate(ctx, bashReq(ceilingBot, "sess", "task", "/work", cmd))
			if d.Verdict == VerdictAllow || d.PendingID == "" || d.Actor == AllowThroughSource {
				t.Fatalf("%s %+v", cmd, d)
			}
		})
	}
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	d := e.Evaluate(ctx, bashReq(ceilingBot, "sess", "task", "/work", "git remote; echo hi"))
	if d.Verdict == VerdictAllow || d.PendingID == "" {
		t.Fatalf("critical compound %+v", d)
	}
}

func TestAllowCeilingHardAskPaths(t *testing.T) {
	ctx := context.Background()
	ws := t.TempDir()
	outside := filepath.Join(t.TempDir(), "out.txt")
	secret := filepath.Join(t.TempDir(), ".ssh", "id_ed25519")
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelHigh})
	writeRaw, _ := json.Marshal(map[string]string{"file_path": outside})
	write := Request{
		BotID: ceilingBot, SessionID: "sess", RunID: "run", TaskID: "task",
		Cwd: ws, Workspace: ws, ToolName: "Write", ToolInput: writeRaw,
	}
	wd := e.Evaluate(ctx, write)
	if wd.Verdict == VerdictAllow || wd.PendingID == "" || wd.Level != LevelHigh {
		t.Fatalf("write %+v", wd)
	}
	rd := e.Evaluate(ctx, readReq(ceilingBot, ws, ws, secret))
	if rd.Verdict == VerdictAllow || rd.PendingID == "" {
		t.Fatalf("read %+v", rd)
	}
	if rd.Level != LevelHigh && rd.Level != LevelCritical {
		t.Fatalf("read level %+v", rd)
	}
}

func TestAllowCeilingGitRisk(t *testing.T) {
	ctx := context.Background()
	plant := []struct {
		name string
		fn   func(t *testing.T, ws, home, userHome string)
	}{
		{name: "attributes-filter", fn: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".gitattributes"), "* filter=x\n")
		}},
		{name: "config-fsmonitor", fn: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = x\n")
		}},
		{name: "config-pager", fn: func(t *testing.T, ws, _, _ string) {
			writeGit(t, ws, "[core]\n\trepositoryformatversion = 0\n\tpager = less\n")
		}},
		{name: "executable-hook", fn: func(t *testing.T, ws, _, _ string) {
			mustWrite(t, filepath.Join(ws, ".git", "hooks", "pre-commit"), "#!/bin/sh\n")
			if err := os.Chmod(filepath.Join(ws, ".git", "hooks", "pre-commit"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range plant {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t)
			ws, home, userHome := cleanRepo(t)
			e.SetBotContext(ceilingBot, ws, nil)
			e.SetBotRuntime(ceilingBot, home, userHome, nil)
			e.SnapshotBot(ceilingBot)
			tc.fn(t, ws, home, userHome)
			e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
			req := bashReq(ceilingBot, "sess", "task", ws, "git remote")
			req.Workspace = ws
			d := e.Evaluate(ctx, req)
			if d.Verdict == VerdictAllow || d.PendingID == "" {
				t.Fatalf("%s %+v", tc.name, d)
			}
		})
	}
	t.Run("baseline-drift", func(t *testing.T) {
		e := testEngine(t)
		ws, home, userHome := cleanRepo(t)
		e.SetBotContext(ceilingBot, ws, nil)
		e.SetBotRuntime(ceilingBot, home, userHome, nil)
		e.SnapshotBot(ceilingBot)
		writeGit(t, ws, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")
		e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
		req := bashReq(ceilingBot, "sess", "task", ws, "git status")
		req.Workspace = ws
		d := e.Evaluate(ctx, req)
		if d.Verdict == VerdictAllow || d.PendingID == "" {
			t.Fatalf("drift %+v", d)
		}
	})
}

func TestAllowCeilingAskRuleWins(t *testing.T) {
	ctx := context.Background()
	for _, scope := range []string{ScopeBot, ScopeGlobal} {
		t.Run(scope, func(t *testing.T) {
			e := testEngine(t)
			e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
			rule := Rule{Effect: EffectAsk, Argv: []string{"git", "status"}, Tool: ToolShell, Scope: scope}
			if scope == ScopeBot {
				rule.BotID = ceilingBot
			}
			if _, err := e.SaveRule(rule); err != nil {
				t.Fatal(err)
			}
			d := e.Evaluate(ctx, bashReq(ceilingBot, "sess", "task", "/work", "git status"))
			if d.Verdict == VerdictAllow || d.PendingID == "" || d.Actor == AllowThroughSource {
				t.Fatalf("%s %+v", scope, d)
			}
		})
	}
}

func TestAllowCeilingAuditFailureDenies(t *testing.T) {
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
	e.audit.close()
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "git status"))
	if d.Verdict != VerdictDeny || d.PendingID != "" || d.Actor != "fail-closed" {
		t.Fatalf("ceiling %+v", d)
	}
	asked := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "echo hi"))
	if asked.Verdict == VerdictAllow || asked.PendingID == "" {
		t.Fatalf("human %+v", asked)
	}
}

func TestSetAllowCeilingsDropsBogus(t *testing.T) {
	e := testEngine(t)
	const other = "33333333-3333-4333-8333-333333333333"
	const padded = "44444444-4444-4444-8444-444444444444"
	e.SetAllowCeilings("hook", map[string]Level{
		ceilingBot:                             "bogus",
		ceilingOther:                           "",
		other:                                  LevelUnclassified,
		padded:                                 " low ",
		"55555555-5555-4555-8555-555555555555": "HIGH",
	})
	if len(e.ceilings) != 0 {
		t.Fatalf("ceilings %#v", e.ceilings)
	}
	e.SetAllowCeilings("hook", map[string]Level{
		" " + strings.ToUpper(ceilingBot) + " ": LevelLow,
		ceilingBot:                              LevelHigh,
	})
	if len(e.ceilings) != 0 {
		t.Fatalf("duplicate ceilings %#v", e.ceilings)
	}
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow, other: "nope"})
	if len(e.ceilings) != 1 || e.ceilings[ceilingBot] != LevelLow {
		t.Fatalf("kept %#v", e.ceilings)
	}
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "git status"))
	if d.Verdict != VerdictAllow || d.Actor != AllowThroughSource {
		t.Fatalf("%+v", d)
	}
}

func TestAllowCeilingCompareBeforeRaise(t *testing.T) {
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
	e.SetInspectHook(func(context.Context, Request) {
		if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelHigh}}); err != nil {
			t.Fatal(err)
		}
	})
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "git status"))
	if d.Verdict == VerdictAllow || d.Level != LevelHigh || d.PendingID == "" {
		t.Fatalf("%+v", d)
	}
}

func TestAllowCeilingNotOSGated(t *testing.T) {
	prev := autoAllowGOOS
	autoAllowGOOS = "darwin"
	t.Cleanup(func() { autoAllowGOOS = prev })
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelLow})
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "git status"))
	if d.Verdict != VerdictAllow || d.Actor != AllowThroughSource || d.Level != LevelLow {
		t.Fatalf("%+v", d)
	}
}

func TestAllowCeilingPolicyPath(t *testing.T) {
	ctx := context.Background()
	pol := filepath.Join(t.TempDir(), "policy.toml")
	e := testEngine(t)
	e.SetCriticalPaths([]string{pol})
	e.SetPolicyPaths(pol)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelHigh})
	high := e.Evaluate(ctx, bashReq(ceilingBot, "sess", "task", "/work", "git status "+pol))
	if high.Verdict == VerdictAllow || high.PendingID == "" || high.Level != LevelCritical {
		t.Fatalf("high %+v", high)
	}
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelCritical})
	crit := e.Evaluate(ctx, bashReq(ceilingBot, "sess", "task", "/work", "git status "+pol))
	if crit.Verdict == VerdictAllow || crit.PendingID == "" {
		t.Fatalf("critical %+v", crit)
	}
}
