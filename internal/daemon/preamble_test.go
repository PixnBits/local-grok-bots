package daemon

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestToolRoundNarrationIsNotTheReply(t *testing.T) {
	var mu sync.Mutex
	var reqs [][]model.Message
	var n atomic.Int32
	app := newApp(t, "", fakeModel{fn: func(req model.ChatRequest) (model.ChatResponse, error) {
		mu.Lock()
		reqs = append(reqs, append([]model.Message(nil), req.Messages...))
		mu.Unlock()
		switch n.Add(1) {
		case 1:
			return model.ChatResponse{
				Content: "Let me check the roster.",
				ToolCalls: []model.ToolCall{{
					Name: "list_bots", Arguments: map[string]any{},
				}},
			}, nil
		case 2:
			return model.ChatResponse{Content: "Ada is the only bot."}, nil
		default:
			return model.ChatResponse{Content: "still just Ada."}, nil
		}
	}})
	srv := serve(t, app)
	_, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Ada", "description": "look things up"}, "")
	var bot store.Bot
	decodeJSON(t, b, &bot)
	_, b = do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "who is here"}, "")
	var posted struct {
		RunID string `json:"run_id"`
	}
	decodeJSON(t, b, &posted)
	waitIdle(t, srv.URL, bot.ID, "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/bots/"+bot.ID+"/thread/stream?run_id="+posted.RunID, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var streamed bool
	sc := bufio.NewScanner(res.Body)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
		if event == "token" && strings.Contains(line, "Let me check the roster.") {
			streamed = true
		}
		if event == "done" && strings.HasPrefix(line, "data:") {
			break
		}
	}
	if !streamed {
		t.Fatal("narration was not streamed")
	}

	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID+"/thread", nil, "")
	var thread struct {
		Messages []store.Message `json:"messages"`
	}
	decodeJSON(t, b, &thread)
	var botTexts []string
	for _, m := range thread.Messages {
		if m.Role == "bot" {
			botTexts = append(botTexts, m.Content)
		}
		if strings.Contains(m.Content, "Let me check the roster.") {
			t.Fatalf("narration stored on the thread: %#v", thread.Messages)
		}
	}
	if len(botTexts) != 1 || botTexts[0] != "Ada is the only bot." {
		t.Fatalf("bot texts %#v", botTexts)
	}

	mu.Lock()
	if len(reqs) < 2 {
		t.Fatalf("model calls %d", len(reqs))
	}
	follow := reqs[1]
	sys := reqs[0][0].Content
	mu.Unlock()
	if !strings.Contains(sys, `Do not reply with only an announcement such as "Let me check."`) {
		t.Fatalf("prompt missing the announcement rule: %s", sys)
	}
	if !sawRoleContent(follow, "assistant", "Let me check the roster.") {
		t.Fatal("in-run follow-up lost the narration")
	}

	do(t, "POST", srv.URL+"/api/bots/"+bot.ID+"/thread/messages", map[string]string{"content": "and now"}, "")
	waitIdle(t, srv.URL, bot.ID, "")
	mu.Lock()
	defer mu.Unlock()
	if len(reqs) < 3 {
		t.Fatalf("expected a later turn, calls=%d", len(reqs))
	}
	later := reqs[2]
	if sawRoleContent(later, "assistant", "Let me check the roster.") {
		t.Fatal("later turn was shown the narration")
	}
	if !sawRoleContent(later, "assistant", "Ada is the only bot.") {
		t.Fatal("later turn lost the stored reply")
	}
}

func sawRoleContent(msgs []model.Message, role, content string) bool {
	for _, m := range msgs {
		if m.Role == role && m.Content == content {
			return true
		}
	}
	return false
}

func TestZoneLabelUsesTZName(t *testing.T) {
	t.Setenv("TZ", "America/Phoenix")
	loc, err := time.LoadLocation("America/Phoenix")
	if err != nil {
		t.Skip("no tzdata")
	}
	if got := zoneLabel(time.Now().In(loc)); got != "America/Phoenix, MST" {
		t.Fatalf("zoneLabel = %q", got)
	}
}
