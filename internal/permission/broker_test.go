package permission

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestRuleMatch(t *testing.T) {
	if !ruleMatches("Bash(git status*)", "Bash", "git status -sb") {
		t.Fatal("status pattern should match")
	}
	if ruleMatches("Bash(git status*)", "Bash", "git diff") {
		t.Fatal("status pattern matched diff")
	}
	if !ruleMatches("Read", "read", "") {
		t.Fatal("bare tool name should match any args")
	}
	if ruleMatches("Bash", "Read", "") {
		t.Fatal("bash matched read")
	}
	if !ruleMatches("mcp__*", "mcp__srv__tool", "") {
		t.Fatal("tool glob missed")
	}
	if ruleMatches("Bash(git status*)", "Bash", "") {
		t.Fatal("scoped rule matched an empty command")
	}
}

func TestEvaluateOrder(t *testing.T) {
	req := Request{ID: "1", RunID: "run", BotID: "bot", SessionID: "sess", Tool: "Bash", Args: map[string]any{"command": "git status"}}
	bypass := policy.Permission{
		Mode:          "bypassPermissions",
		Allow:         []string{"Bash(git status*)", "Read"},
		Deny:          []string{"Bash(rm *)"},
		Ask:           []string{"Bash(git push*)"},
		UIPrompts:     true,
		PromptTimeout: time.Second,
	}

	t.Run("hook deny beats mode and allow", func(t *testing.T) {
		b := New(Options{})
		b.AddHook(func(Request) HookResult { return HookResult{Decision: "deny", Rule: "hook-deny"} })
		out := b.Evaluate(context.Background(), bypass, req)
		if out.Decision != Deny || out.Source != "hook" || out.Rule != "hook-deny" || out.Behavior != "deny" {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("deny rule beats hook allow and bypass", func(t *testing.T) {
		b := New(Options{})
		b.AddHook(func(Request) HookResult { return HookResult{Decision: "allow", Rule: "hook-allow"} })
		rm := req
		rm.Args = map[string]any{"command": "rm -rf /tmp/x"}
		out := b.Evaluate(context.Background(), bypass, rm)
		if out.Decision != Deny || out.Source != "policy" || out.Rule != "Bash(rm *)" {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("ask beats bypass and allow", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		push := req
		push.Args = map[string]any{"command": "git push origin"}
		pol := bypass
		pol.Allow = append(pol.Allow, "Bash(git push*)")
		out := b.Evaluate(context.Background(), pol, push)
		if out.Decision != Deny || out.Source != "no_ui" || out.Rule != "Bash(git push*)" || out.Behavior != "deny" {
			t.Fatalf("ask fell through to allow: %+v", out)
		}
	})

	t.Run("hook allow beats mode", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		b.AddHook(func(Request) HookResult { return HookResult{Decision: "allow", Rule: "hook-allow"} })
		pol := policy.Permission{Mode: "default", UIPrompts: true}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Allow || out.Source != "hook" || out.Rule != "hook-allow" || out.Behavior != "allow" {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("mode beats allow and canUseTool", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		pol := policy.Permission{Mode: "always-allow", UIPrompts: true}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Allow || out.Source != "policy" || out.Rule != "always-allow" {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("allow beats canUseTool", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		pol := policy.Permission{Mode: "default", Allow: []string{"Bash(git status*)"}, UIPrompts: true}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Allow || out.Source != "policy" || out.Rule != "Bash(git status*)" {
			t.Fatalf("%+v", out)
		}
	})

	t.Run("canUseTool is last", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		pol := policy.Permission{Mode: "default", Allow: []string{"Read"}, UIPrompts: true}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Deny || out.Source != "no_ui" || out.Behavior != "deny" {
			t.Fatalf("%+v", out)
		}
	})
}

func TestAbsentUIDenies(t *testing.T) {
	req := Request{RunID: "run", BotID: "bot", Tool: "Bash", Args: map[string]any{"command": "ls"}}
	var events []string
	b := New(Options{
		UIPresent: func(string) bool { return false },
		Publish:   func(_, event string, _ any) { events = append(events, event) },
	})
	out := b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second}, req)
	if out.Source != "no_ui" || out.Decision != Deny {
		t.Fatalf("%+v", out)
	}
	if len(events) != 1 || events[0] != "permission_decision" {
		t.Fatalf("events %v", events)
	}
	off := b.Evaluate(context.Background(), policy.Permission{UIPrompts: false}, req)
	if off.Source != "no_ui" {
		t.Fatalf("prompts off: %+v", off)
	}
}

func TestTimeoutDenies(t *testing.T) {
	b := New(Options{UIPresent: func(string) bool { return true }})
	start := time.Now()
	out := b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: 40 * time.Millisecond}, Request{
		RunID: "run", BotID: "bot", Tool: "Bash",
	})
	if out.Source != "timeout" || out.Decision != Deny || out.Message == "" {
		t.Fatalf("%+v", out)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
	if err := b.DecideFor("bot", "run", out.ID, Deny); !errors.Is(err, ErrDecided) {
		t.Fatalf("deciding a finished request: %v", err)
	}
}

func TestCancelDenies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := New(Options{UIPresent: func(string) bool { return true }})
	out := b.Evaluate(ctx, policy.Permission{UIPrompts: true, PromptTimeout: time.Minute}, Request{
		RunID: "run", BotID: "bot", Tool: "Bash",
	})
	if out.Source != "cancel" || out.Decision != Deny {
		t.Fatalf("%+v", out)
	}
}

func TestAllowSessionRefusedWithoutManagedPolicy(t *testing.T) {
	b := New(Options{UIPresent: func(string) bool { return true }})
	req := Request{ID: "req-1", RunID: "run", BotID: "bot", SessionID: "sess", Tool: "Bash", Args: map[string]any{"command": "ls"}}
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second, AllowSessionGrants: false}, req)
	}()
	waitForPending(t, b, "req-1")
	if err := b.DecideFor("bot", "run", "req-1", AllowSession); !errors.Is(err, ErrSessionGrant) {
		t.Fatalf("session grant err %v", err)
	}
	if err := b.DecideFor("other", "run", "req-1", Deny); !errors.Is(err, ErrMismatch) {
		t.Fatalf("mismatch err %v", err)
	}
	if err := b.DecideFor("bot", "run", "missing", Deny); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing err %v", err)
	}
	if err := b.DecideFor("bot", "run", "req-1", "allow"); !errors.Is(err, ErrDecision) {
		t.Fatalf("bad decision %v", err)
	}
	if err := b.DecideFor("bot", "run", "req-1", Deny); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.Source != "ui" || out.Decision != Deny || out.Behavior != "deny" {
		t.Fatalf("%+v", out)
	}
	fresh := New(Options{})
	if err := fresh.DecideFor("bot", "run", "req-1", AllowOnce); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restart still had the request: %v", err)
	}
}

func TestAllowSessionRemembersTool(t *testing.T) {
	b := New(Options{UIPresent: func(string) bool { return true }})
	req := Request{ID: "req-2", RunID: "run", BotID: "bot", SessionID: "sess", Tool: "Bash"}
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second, AllowSessionGrants: true}, req)
	}()
	waitForPending(t, b, "req-2")
	if err := b.DecideFor("bot", "run", "req-2", AllowSession); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.Decision != AllowSession || out.Behavior != "allow" || out.Source != "ui" {
		t.Fatalf("first %+v", out)
	}
	again := b.Evaluate(context.Background(), policy.Permission{UIPrompts: true}, Request{
		RunID: "run-2", BotID: "bot", SessionID: "sess", Tool: "bash",
	})
	if again.Decision != Allow || again.Source != "ui" || again.Rule != "session" {
		t.Fatalf("grant %+v", again)
	}
	blocked := b.Evaluate(context.Background(), policy.Permission{Deny: []string{"Bash"}}, Request{
		RunID: "run-3", BotID: "bot", SessionID: "sess", Tool: "Bash",
	})
	if blocked.Source != "policy" || blocked.Decision != Deny {
		t.Fatalf("deny did not beat the session grant: %+v", blocked)
	}
}

func TestAuditRedactsSecretArg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var saw map[string]any
	b := New(Options{
		Audit: func(fields map[string]any) {
			log.Write(fields)
			saw = fields
		},
	})
	secret := "sk-supersecretvalue12"
	out := b.Evaluate(context.Background(), policy.Permission{Deny: []string{"Bash(echo *)"}}, Request{
		ID: "req", RunID: "run-9", BotID: "bot-9", Tool: "Bash",
		Args: map[string]any{"command": "echo " + secret, "api_key": secret},
	})
	if out.Source != "policy" || out.Decision != Deny || out.Rule != "Bash(echo *)" {
		t.Fatalf("%+v", out)
	}
	for _, key := range []string{"source", "rule", "tool", "arguments", "bot_id", "run_id", "time", "decision"} {
		if saw[key] == nil || saw[key] == "" {
			t.Fatalf("audit field %s missing in %#v", key, saw)
		}
	}
	if saw["source"] != "policy" || saw["tool"] != "Bash" || saw["bot_id"] != "bot-9" || saw["run_id"] != "run-9" || saw["decision"] != Deny {
		t.Fatalf("audit %#v", saw)
	}
	if strings.Contains(saw["arguments"].(string), secret) {
		t.Fatalf("arguments leaked: %s", saw["arguments"])
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), secret) || !strings.Contains(string(body), `"event":"permission_decision"`) {
		t.Fatalf("file %s", body)
	}
	var rec map[string]any
	if err := json.Unmarshal(body, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, rec["time"].(string)); err != nil {
		t.Fatal(err)
	}
}

func TestTransportIsRecorded(t *testing.T) {
	var event map[string]any
	var recorded map[string]any
	b := New(Options{
		Publish: func(_, name string, payload any) {
			if name == "permission_decision" {
				event = payload.(map[string]any)
			}
		},
		Audit: func(fields map[string]any) { recorded = fields },
	})
	out := b.Evaluate(context.Background(), policy.Permission{Deny: []string{"Bash"}}, Request{
		RunID: "r", BotID: "b", Tool: "Bash", Transport: "stream_control",
	})
	if out.Decision != Deny || event["transport"] != "stream_control" || recorded["transport"] != "stream_control" {
		t.Fatalf("out %+v event %#v audit %#v", out, event, recorded)
	}
	plain := b.Evaluate(context.Background(), policy.Permission{Deny: []string{"Read"}}, Request{
		RunID: "r", BotID: "b", Tool: "Read",
	})
	if plain.Decision != Deny {
		t.Fatal(plain)
	}
	if _, ok := event["transport"]; ok {
		t.Fatalf("empty transport was recorded: %#v", event)
	}
}

func waitForPending(t *testing.T, b *Broker, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		_, ok := b.pending[id]
		b.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("request %s was not pending", id)
}
