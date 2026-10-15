package permission

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func sampleQuestion(multi bool) map[string]any {
	return map[string]any{
		"questions": []any{
			map[string]any{
				"question":    "Which library?",
				"header":      "Lib",
				"multiSelect": multi,
				"options": []any{
					map[string]any{"label": "Go", "description": "Go toolchain"},
					map[string]any{"label": "Rust", "description": "Rust toolchain"},
				},
			},
		},
	}
}

func TestAskUserQuestionIsNeverAutoAllowed(t *testing.T) {
	req := Request{ID: "q", RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: sampleQuestion(false)}
	bypass := policy.Permission{
		Mode: "bypassPermissions", Allow: []string{"AskUserQuestion"}, UIPrompts: true,
	}
	t.Run("deny rule wins", func(t *testing.T) {
		b := New(Options{})
		pol := bypass
		pol.Deny = []string{"AskUserQuestion"}
		out := b.Evaluate(context.Background(), pol, req)
		if out.Decision != Deny || out.Source != "policy" || out.Rule != "AskUserQuestion" || out.UpdatedInput != nil {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("hook deny wins", func(t *testing.T) {
		b := New(Options{})
		b.AddHook(func(Request) HookResult { return HookResult{Decision: "deny", Rule: "stop"} })
		out := b.Evaluate(context.Background(), bypass, req)
		if out.Source != "hook" || out.Decision != Deny {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("bypass and allow do not answer", func(t *testing.T) {
		b := New(Options{UIPresent: func(string) bool { return false }})
		b.AddHook(func(Request) HookResult { return HookResult{Decision: "allow", Rule: "hook-allow"} })
		out := b.Evaluate(context.Background(), bypass, req)
		if out.Source != "no_ui" || out.Decision != Deny || out.Message != "The user did not answer the question (no_ui)." {
			t.Fatalf("%+v", out)
		}
	})
	t.Run("other case is not a question", func(t *testing.T) {
		b := New(Options{})
		other := req
		other.Tool = "askuserquestion"
		out := b.Evaluate(context.Background(), bypass, other)
		if out.Decision != Allow || out.Source != "policy" {
			t.Fatalf("folded name was treated as a question: %+v", out)
		}
	})
}

func TestMalformedQuestionDenies(t *testing.T) {
	var events []string
	var audit map[string]any
	b := New(Options{
		Publish:   func(_, event string, _ any) { events = append(events, event) },
		Audit:     func(fields map[string]any) { audit = fields },
		UIPresent: func(string) bool { return true },
	})
	out := b.Evaluate(context.Background(), policy.Permission{UIPrompts: true}, Request{
		ID: "bad", RunID: "run", BotID: "bot", Tool: "AskUserQuestion",
		Args: map[string]any{"questions": []any{}},
	})
	if out.Decision != Deny || out.Source != "policy" || out.Rule != "malformed" || out.Message != "AskUserQuestion input is malformed" {
		t.Fatalf("%+v", out)
	}
	if len(events) != 1 || events[0] != "permission_decision" {
		t.Fatalf("events %v", events)
	}
	if audit["kind"] != "question" || audit["answered"] != 0 {
		t.Fatalf("audit %#v", audit)
	}
}

func TestAnswerQuestion(t *testing.T) {
	secret := "sk-supersecretvalue12"
	args := map[string]any{
		"questions": []any{
			map[string]any{
				"question":    "Which library " + secret + "?",
				"header":      "Lib",
				"multiSelect": false,
				"options": []any{
					map[string]any{"label": "Go", "description": "Go toolchain"},
					map[string]any{"label": "Rust", "description": "Rust toolchain"},
				},
			},
			map[string]any{
				"question":    "Which libraries?",
				"header":      "Libs",
				"multiSelect": true,
				"options": []any{
					map[string]any{"label": "Go", "description": "Go toolchain"},
					map[string]any{"label": "Rust", "description": "Rust toolchain"},
					map[string]any{"label": "Zig", "description": "Zig toolchain"},
				},
			},
		},
	}
	// Evaluate publishes on its own goroutine, and pending is set before
	// publish, so waitForPending does not synchronize these captures.
	requestCh := make(chan map[string]any, 2)
	decisionCh := make(chan map[string]any, 2)
	recordedCh := make(chan map[string]any, 2)
	b := New(Options{
		UIPresent: func(string) bool { return true },
		Publish: func(_, event string, payload any) {
			m := payload.(map[string]any)
			switch event {
			case "permission_request":
				requestCh <- m
			case "permission_decision":
				decisionCh <- m
			}
		},
		Audit: func(fields map[string]any) { recordedCh <- fields },
	})
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{
			Mode: "bypassPermissions", Allow: []string{"AskUserQuestion"},
			UIPrompts: true, PromptTimeout: time.Second, AllowSessionGrants: true,
		}, Request{ID: "q1", RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: args})
	}()
	waitForPending(t, b, "q1")
	var request map[string]any
	select {
	case request = <-requestCh:
	case <-time.After(2 * time.Second):
		t.Fatal("permission_request was not published")
	}
	if request["kind"] != "question" || request["session_allowed"] != false {
		t.Fatalf("request %#v", request)
	}
	blob, _ := json.Marshal(request)
	if strings.Contains(string(blob), secret) {
		t.Fatalf("request leaked the secret: %s", blob)
	}
	if err := b.DecideFor("bot", "run", "q1", AllowOnce); !errors.Is(err, ErrAnswer) {
		t.Fatalf("allow_once on a question: %v", err)
	}
	if err := b.Answer("bot", "run", "q1", map[string]string{"nope": "Go"}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("unknown key: %v", err)
	}
	preview := "card"
	notes := "because"
	if err := b.Answer("bot", "run", "q1", map[string]string{
		"Which library [redacted]?": "Go",
		"Which libraries?":          "Go, Rust",
	}, map[string]Note{
		"Which libraries?": {Preview: &preview, Notes: &notes},
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Answer("bot", "run", "q1", map[string]string{"Which libraries?": "Go"}, nil); !errors.Is(err, ErrDecided) {
		t.Fatalf("second answer: %v", err)
	}
	out := <-done
	if out.Behavior != "allow" || out.Decision != Answer || out.Source != "ui" || out.UpdatedInput == nil {
		t.Fatalf("%+v", out)
	}
	raw, err := json.Marshal(out.UpdatedInput)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"annotations":{"Which libraries?":{"notes":"because","preview":"card"}},"answers":{"Which libraries?":"Go, Rust","Which library sk-supersecretvalue12?":"Go"},"questions":[{"header":"Lib","multiSelect":false,"options":[{"description":"Go toolchain","label":"Go"},{"description":"Rust toolchain","label":"Rust"}],"question":"Which library sk-supersecretvalue12?"},{"header":"Libs","multiSelect":true,"options":[{"description":"Go toolchain","label":"Go"},{"description":"Rust toolchain","label":"Rust"},{"description":"Zig toolchain","label":"Zig"}],"question":"Which libraries?"}]}`
	if string(raw) != want {
		t.Fatalf("updatedInput\n%s\nwant\n%s", raw, want)
	}
	var decision map[string]any
	select {
	case decision = <-decisionCh:
	case <-time.After(2 * time.Second):
		t.Fatal("permission_decision was not published")
	}
	if decision["kind"] != "question" || decision["answered"] != 2 || decision["decision"] != Answer {
		t.Fatalf("decision %#v", decision)
	}
	if _, ok := decision["answers"]; ok {
		t.Fatalf("decision event carried answers: %#v", decision)
	}
	var recorded map[string]any
	select {
	case recorded = <-recordedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("audit record was not published")
	}
	if recorded["kind"] != "question" || recorded["answered"] != 2 || recorded["source"] != "ui" {
		t.Fatalf("audit %#v", recorded)
	}
	auditAnswers, _ := json.Marshal(recorded["answers"])
	if strings.Contains(string(auditAnswers), secret) || !strings.Contains(string(auditAnswers), "[redacted]") {
		t.Fatalf("audit answers %s", auditAnswers)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	again := b.Evaluate(ctx, policy.Permission{UIPrompts: true, PromptTimeout: time.Minute}, Request{
		RunID: "run-2", BotID: "bot", Tool: "AskUserQuestion", Args: sampleQuestion(false),
	})
	if again.Decision == Allow || again.Source == "ui" && again.Rule == "session" {
		t.Fatalf("session grant answered a question: %+v", again)
	}
}

func TestAnswerOnOrdinaryTool(t *testing.T) {
	b := New(Options{UIPresent: func(string) bool { return true }})
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second}, Request{
			ID: "b1", RunID: "run", BotID: "bot", Tool: "Bash",
		})
	}()
	waitForPending(t, b, "b1")
	if err := b.Answer("bot", "run", "b1", map[string]string{"q": "a"}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("answer on bash: %v", err)
	}
	if err := b.DecideFor("bot", "run", "b1", Deny); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.Decision != Deny || out.Source != "ui" || out.Message != "denied by user" {
		t.Fatalf("%+v", out)
	}
}

func TestQuestionTimeoutAndFreeText(t *testing.T) {
	b := New(Options{UIPresent: func(string) bool { return true }})
	out := b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: 30 * time.Millisecond}, Request{
		RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: sampleQuestion(false),
	})
	if out.Source != "timeout" || out.Message != "The user did not answer the question (timeout)." || out.UpdatedInput != nil {
		t.Fatalf("%+v", out)
	}

	b = New(Options{UIPresent: func(string) bool { return true }})
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second}, Request{
			ID: "free", RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: sampleQuestion(false),
		})
	}()
	waitForPending(t, b, "free")
	if err := b.Answer("bot", "run", "free", map[string]string{"Which library?": "   "}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("blank answer: %v", err)
	}
	if err := b.Answer("bot", "run", "free", map[string]string{"Which library?": "my own pick"}, nil); err != nil {
		t.Fatal(err)
	}
	out = <-done
	raw, _ := json.Marshal(out.UpdatedInput["answers"])
	if string(raw) != `{"Which library?":"my own pick"}` {
		t.Fatalf("free text %s", raw)
	}

	b = New(Options{UIPresent: func(string) bool { return true }})
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: time.Second}, Request{
			ID: "multi", RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: sampleQuestion(true),
		})
	}()
	waitForPending(t, b, "multi")
	if err := b.Answer("bot", "run", "multi", map[string]string{"Which library?": "Go, "}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("trailing join: %v", err)
	}
	if err := b.Answer("bot", "run", "multi", map[string]string{"Which library?": "Go, my own"}, nil); err != nil {
		t.Fatal(err)
	}
	out = <-done
	raw, _ = json.Marshal(out.UpdatedInput["answers"])
	if string(raw) != `{"Which library?":"Go, my own"}` {
		t.Fatalf("multi %s", raw)
	}
}

func TestFreeTextAnswerCap(t *testing.T) {
	pol := policy.Permission{UIPrompts: true, PromptTimeout: time.Second}
	start := func(id string, args map[string]any) (*Broker, chan Outcome) {
		t.Helper()
		b := New(Options{UIPresent: func(string) bool { return true }})
		done := make(chan Outcome, 1)
		go func() {
			done <- b.Evaluate(context.Background(), pol, Request{
				ID: id, RunID: "run", BotID: "bot", Tool: "AskUserQuestion", Args: args,
			})
		}()
		waitForPending(t, b, id)
		return b, done
	}
	b, done := start("cap", sampleQuestion(false))
	over := strings.Repeat("a", maxFreeAnswer+1)
	if err := b.Answer("bot", "run", "cap", map[string]string{"Which library?": over}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("over cap: %v", err)
	}
	exact := strings.Repeat("b", maxFreeAnswer)
	if err := b.Answer("bot", "run", "cap", map[string]string{"Which library?": exact}, nil); err != nil {
		t.Fatal(err)
	}
	out := <-done
	raw, _ := json.Marshal(out.UpdatedInput["answers"])
	if string(raw) != `{"Which library?":"`+exact+`"}` {
		t.Fatalf("capped answer %s", raw)
	}

	label := strings.Repeat("c", maxFreeAnswer+8)
	args := map[string]any{
		"questions": []any{map[string]any{
			"question": "Which library?", "header": "Lib", "multiSelect": false,
			"options": []any{
				map[string]any{"label": label, "description": "long"},
				map[string]any{"label": "Rust", "description": "Rust toolchain"},
			},
		}},
	}
	b, done = start("label", args)
	if err := b.Answer("bot", "run", "label", map[string]string{"Which library?": label}, nil); err != nil {
		t.Fatalf("long label: %v", err)
	}
	out = <-done
	if out.UpdatedInput["answers"].(map[string]any)["Which library?"] != label {
		t.Fatalf("label answer %+v", out.UpdatedInput["answers"])
	}

	b, done = start("multi", sampleQuestion(true))
	if err := b.Answer("bot", "run", "multi", map[string]string{"Which library?": "Go, " + over}, nil); !errors.Is(err, ErrAnswer) {
		t.Fatalf("multi free text: %v", err)
	}
	b.DecideFor("bot", "run", "multi", Deny)
	<-done
}
