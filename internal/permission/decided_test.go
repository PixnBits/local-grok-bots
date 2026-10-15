package permission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// TestDecideTwiceIsOneDecision covers a double-clicked Allow: one decision
// event, the second answer refused, and no timeout after the answer.
func TestDecideTwiceIsOneDecision(t *testing.T) {
	var mu sync.Mutex
	var decisions []map[string]any
	reqs := make(chan string, 1)
	b := New(Options{
		UIPresent: func(string) bool { return true },
		Publish: func(_, event string, payload any) {
			m := payload.(map[string]any)
			switch event {
			case "permission_request":
				reqs <- m["id"].(string)
			case "permission_decision":
				mu.Lock()
				decisions = append(decisions, m)
				mu.Unlock()
			}
		},
	})
	done := make(chan Outcome, 1)
	go func() {
		done <- b.Evaluate(context.Background(), policy.Permission{UIPrompts: true, PromptTimeout: 80 * time.Millisecond}, Request{RunID: "run", BotID: "bot", Tool: "Bash"})
	}()
	id := <-reqs
	if err := b.DecideFor("bot", "run", id, AllowOnce); err != nil {
		t.Fatal(err)
	}
	if err := b.DecideFor("bot", "run", id, AllowOnce); !errors.Is(err, ErrDecided) {
		t.Fatalf("second answer: %v", err)
	}
	if err := b.DecideFor("other", "run", id, AllowOnce); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other bot: %v", err)
	}
	out := <-done
	if out.Behavior != "allow" || out.Source != "ui" {
		t.Fatalf("%+v", out)
	}
	time.Sleep(150 * time.Millisecond) // past the prompt timeout
	mu.Lock()
	defer mu.Unlock()
	if len(decisions) != 1 || decisions[0]["decision"] != AllowOnce {
		t.Fatalf("decisions %v", decisions)
	}
}
