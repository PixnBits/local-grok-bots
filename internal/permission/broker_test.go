package permission

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		pol.PromptTimeout = 20 * time.Millisecond
		out := b.Evaluate(context.Background(), pol, push)
		if out.Decision != Deny || out.Source != "timeout" || out.Rule != "Bash(git push*)" || out.Behavior != "deny" {
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
		pol := policy.Permission{Mode: "default", Allow: []string{"Read"}, UIPrompts: true, PromptTimeout: 20 * time.Millisecond}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Deny || out.Source != "timeout" || out.Behavior != "deny" {
			t.Fatalf("%+v", out)
		}
	})
}

// A request waits for an answer whether or not a page is attached right
// now. Pending lists it for a page that opens later. Only ui_prompts = false
// denies at once.
func TestNoPageStaysPending(t *testing.T) {
	req := Request{RunID: "run", BotID: "bot", Tool: "Bash", Args: map[string]any{"command": "ls"}}
	var mu sync.Mutex
	var events []string
	b := New(Options{
		UIPresent: func(string) bool { return false },
		Publish: func(_, event string, _ any) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		},
	})
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: 10 * time.Second}, req)
	}()
	var list []map[string]any
	for i := 0; i < 200 && len(list) == 0; i++ {
		list = b.Pending("bot")
		time.Sleep(5 * time.Millisecond)
	}
	if len(list) != 1 || list[0]["tool"] != "Bash" || list[0]["run_id"] != "run" || list[0]["deadline"] == "" {
		t.Fatalf("pending %v", list)
	}
	if len(b.Pending("other")) != 0 || b.PendingCounts()["bot"] != 1 {
		t.Fatalf("counts %v", b.PendingCounts())
	}
	id, _ := list[0]["id"].(string)
	select {
	case out := <-done:
		t.Fatalf("resolved without an answer: %+v", out)
	case <-time.After(100 * time.Millisecond):
	}
	if err := b.DecideFor("bot", "run", id, AllowOnce); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.Decision != AllowOnce || out.Source != "ui" || out.Behavior != "allow" {
		t.Fatalf("%+v", out)
	}
	if err := b.DecideFor("bot", "run", id, Deny); err != ErrDecided {
		t.Fatalf("second answer %v", err)
	}
	if len(b.Pending("")) != 0 {
		t.Fatal("still pending")
	}
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "permission_request,permission_decision" {
		t.Fatalf("events %s", got)
	}
	off := b.Evaluate(context.Background(), policy.Permission{UIPrompts: false}, req)
	if off.Source != "no_ui" || off.Decision != Deny {
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

func TestSessionGrantOneTarget(t *testing.T) {
	ws := t.TempDir()
	mustFile(t, ws, "a.txt")
	mustFile(t, ws, "b.txt")
	b := New(Options{UIPresent: func(string) bool { return true }})
	approve := func(id, tool string, args map[string]any) {
		t.Helper()
		done := make(chan Outcome, 1)
		go func() {
			done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second, AllowSessionGrants: true}, Request{
				ID: id, RunID: "run", BotID: "bot", SessionID: "sess", Tool: tool, Workspace: ws, Args: args,
			})
		}()
		waitForPending(t, b, id)
		if err := b.DecideFor("bot", "run", id, AllowSession); err != nil {
			t.Fatal(err)
		}
		out := <-done
		if out.Decision != AllowSession || out.Source != "ui" {
			t.Fatalf("approve %+v", out)
		}
	}
	quiet := policy.Permission{UIPrompts: false}
	approve("c1", "Bash", map[string]any{"command": "pwd"})
	same := b.Evaluate(context.Background(), quiet, Request{
		RunID: "run-2", BotID: "bot", SessionID: "sess", Tool: "bash", Workspace: ws,
		Args: map[string]any{"command": "pwd"},
	})
	if same.Decision != Allow || same.Source != "ui" || same.Rule != "session" {
		t.Fatalf("same command %+v", same)
	}
	otherCmd := b.Evaluate(context.Background(), quiet, Request{
		RunID: "run-3", BotID: "bot", SessionID: "sess", Tool: "Bash", Workspace: ws,
		Args: map[string]any{"command": "ls"},
	})
	if otherCmd.Decision == Allow || otherCmd.Source == "ui" {
		t.Fatalf("other command %+v", otherCmd)
	}
	otherSess := b.Evaluate(context.Background(), quiet, Request{
		RunID: "run-4", BotID: "bot", SessionID: "other", Tool: "Bash", Workspace: ws,
		Args: map[string]any{"command": "pwd"},
	})
	if otherSess.Decision == Allow {
		t.Fatalf("other session %+v", otherSess)
	}
	approve("p1", "Read", map[string]any{"file_path": "a.txt"})
	samePath := b.Evaluate(context.Background(), quiet, Request{
		RunID: "run-5", BotID: "bot", SessionID: "sess", Tool: "Read", Workspace: ws,
		Args: map[string]any{"file_path": "./a.txt"},
	})
	if samePath.Decision != Allow || samePath.Source != "ui" || samePath.Rule != "session" {
		t.Fatalf("same path %+v", samePath)
	}
	otherPath := b.Evaluate(context.Background(), quiet, Request{
		RunID: "run-6", BotID: "bot", SessionID: "sess", Tool: "Read", Workspace: ws,
		Args: map[string]any{"file_path": "b.txt"},
	})
	if otherPath.Decision == Allow || otherPath.Source == "ui" {
		t.Fatalf("other path %+v", otherPath)
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
