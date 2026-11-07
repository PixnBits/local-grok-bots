package permbroker

import (
	"context"
	"strings"
	"testing"
)

const (
	ceilingBot   = "11111111-1111-4111-8111-111111111111"
	ceilingOther = "22222222-2222-4222-8222-222222222222"
)

func TestAllowCeilingDecisions(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		broker  string
		ceiling Level
		forBot  string
		bot     string
		cmd     string
		want    string
		level   Level
		raise   Level
		class   Level
		crit    bool
		deny    bool
	}{
		{name: "at", broker: "hook", ceiling: LevelLow, cmd: "git status", want: "allow", level: LevelLow},
		{name: "below", broker: "hook", ceiling: LevelMedium, cmd: "git status", want: "allow", level: LevelLow},
		{name: "above", broker: "hook", ceiling: LevelMedium, cmd: "git push", want: "ask", level: LevelHigh},
		{name: "policy_raise", broker: "hook", ceiling: LevelMedium, cmd: "git status", want: "ask", level: LevelHigh, raise: LevelHigh},
		{name: "classifier_raise", broker: "hook", ceiling: LevelMedium, cmd: "git status", want: "ask", level: LevelHigh, class: LevelHigh},
		{name: "critical_path", broker: "hook", ceiling: LevelHigh, cmd: "git status", want: "ask", level: LevelCritical, crit: true},
		{name: "deny_wins", broker: "hook", ceiling: LevelCritical, cmd: "git status", want: "deny", deny: true},
		{name: "unclassified", broker: "hook", ceiling: LevelCritical, cmd: "echo hi", want: "ask", level: LevelUnclassified},
		{name: "parse_error", broker: "hook", ceiling: LevelCritical, cmd: "git status \"", want: "ask", level: LevelUnclassified},
		{name: "critical_ceiling_high", broker: "hook", ceiling: LevelHigh, cmd: "gh auth token", want: "ask", level: LevelCritical},
		{name: "critical_ceiling_critical", broker: "hook", ceiling: LevelCritical, cmd: "gh auth token", want: "allow", level: LevelCritical},
		{name: "broker_not_hook", broker: "off", ceiling: LevelCritical, cmd: "git status", want: "ask", level: LevelLow},
		{name: "bot_not_listed", broker: "hook", ceiling: LevelCritical, forBot: ceilingOther, cmd: "git status", want: "ask", level: LevelLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(t)
			bot := tc.bot
			if bot == "" {
				bot = ceilingBot
			}
			owner := tc.forBot
			if owner == "" {
				owner = bot
			}
			if tc.raise != "" {
				if err := e.SetRisks([]RiskEntry{{Tool: "shell", Argv: []string{"git", "status"}, Level: tc.raise}}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.class != "" {
				e.SetClassifier(reportClass{level: tc.class, advisory: "raise", checked: true})
			}
			cmd := tc.cmd
			if tc.crit {
				dir := t.TempDir()
				e.SetCriticalPaths([]string{dir})
				cmd = cmd + " " + dir
			}
			if tc.deny {
				if _, err := e.SaveRule(Rule{
					Effect: EffectDeny, Argv: []string{"git", "status"}, Tool: ToolShell,
					Scope: ScopeBot, BotID: bot,
				}); err != nil {
					t.Fatal(err)
				}
			}
			e.SetAllowCeilings(tc.broker, map[string]Level{owner: tc.ceiling})
			d := e.Evaluate(ctx, bashReq(bot, "sess", "task", "/work", cmd))
			switch tc.want {
			case "allow":
				if d.Verdict != VerdictAllow || d.PendingID != "" || d.Level != tc.level || d.Actor != AllowThroughSource {
					t.Fatalf("%+v", d)
				}
			case "ask":
				if d.Verdict == VerdictAllow || d.PendingID == "" || d.Level != tc.level {
					t.Fatalf("%+v", d)
				}
			case "deny":
				if d.Verdict != VerdictDeny || d.PendingID != "" || !strings.Contains(d.Reason, "denied by rule") {
					t.Fatalf("%+v", d)
				}
			default:
				t.Fatalf("want %q", tc.want)
			}
		})
	}
}

func TestAllowCeilingAudit(t *testing.T) {
	e := testEngine(t)
	e.SetAllowCeilings("hook", map[string]Level{ceilingBot: LevelMedium})
	d := e.Evaluate(context.Background(), bashReq(ceilingBot, "sess", "task", "/work", "git status"))
	if d.Verdict != VerdictAllow || d.Level != LevelLow || d.PendingID != "" {
		t.Fatalf("%+v", d)
	}
	rows := decodeAudit(t, readPermAudit(t, e.dir))
	if len(rows) == 0 {
		t.Fatal("no audit row")
	}
	row := rows[len(rows)-1]
	if row.Source != AllowThroughSource || row.Level != LevelLow || row.Ceiling != LevelMedium {
		t.Fatalf("source %q level %q ceiling %q", row.Source, row.Level, row.Ceiling)
	}
	if row.Decision != VerdictAllow || row.BotID != ceilingBot {
		t.Fatalf("%+v", row)
	}
}
