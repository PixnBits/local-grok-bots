package permbroker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGolden_LocalClassifierLoopback(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("body %s", body)
		}
		bodies = append(bodies, got)
		if strings.Contains(string(body), "secret-token") || strings.Contains(string(body), "file-contents") {
			t.Errorf("request carried extra data %s", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"level": "high", "advisory": "look\nhere"})
	}))
	t.Cleanup(srv.Close)
	if !strings.Contains(srv.URL, "127.0.0.1") {
		t.Fatalf("server %s", srv.URL)
	}
	clf, err := NewLocalClassifier(srv.URL, "local", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = clf.Classify(context.Background(), ClassInput{
		Tool: "shell", Argv: []string{"git", "status", "--token=secret-token"}, Level: LevelLow, Raw: "file-contents",
	})
	e := testEngine(t)
	e.SetClassifier(clf)
	d := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "git status"))
	if d.Level != LevelHigh || d.Verdict == VerdictAllow {
		t.Fatalf("%+v", d)
	}
	if len(bodies) < 2 {
		t.Fatalf("requests %d", len(bodies))
	}
	got := bodies[0]
	if got["tool"] == nil || got["model"] != "local" {
		t.Fatalf("sent %#v", got)
	}
	argv, _ := got["argv"].([]any)
	joined := ""
	for _, a := range argv {
		joined += " " + a.(string)
	}
	if strings.Contains(joined, "secret-token") || !strings.Contains(joined, "[redacted]") {
		t.Fatalf("argv %v", argv)
	}
	for _, body := range bodies {
		for _, k := range []string{"env", "raw", "cwd", "file"} {
			if _, ok := body[k]; ok {
				t.Fatalf("sent %s", k)
			}
		}
	}
	var card Pending
	for _, item := range e.ListPending() {
		if item.ID == d.PendingID {
			card = item
		}
	}
	if card.Advisory.Source != "local model raised this to high" || !card.Advisory.Checked || strings.Contains(card.Advisory.Text, "\n") || card.Advisory.Text != "lookhere" {
		t.Fatalf("card %+v", card.Advisory)
	}
}

func TestLocalClassifierMisses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"level":"nope","advisory":"x","extra":1}`))
	}))
	t.Cleanup(srv.Close)
	clf, err := NewLocalClassifier(srv.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rep := clf.Classify(context.Background(), ClassInput{Tool: "shell", Argv: []string{"git", "status"}, Level: LevelLow})
	if rep.Checked || rep.Level != "" || rep.Advisory != "Not checked" {
		t.Fatalf("%+v", rep)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"level":"critical","advisory":"late"}`))
	}))
	t.Cleanup(slow.Close)
	late, err := NewLocalClassifier(slow.URL, "m", 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	miss := late.Classify(context.Background(), ClassInput{Tool: "shell", Argv: nil, Level: LevelLow})
	if miss.Checked || miss.Advisory != "Not checked" || miss.Level != "" {
		t.Fatalf("timeout %+v", miss)
	}
	if _, err := NewLocalClassifier("http://example.com/v1", "m", 0); err == nil {
		t.Fatal("accepted a public endpoint")
	}
	if _, err := NewLocalClassifier("http://192.168.1.1/v1", "m", 0); err == nil {
		t.Fatal("accepted a lan endpoint")
	}
}

func TestLocalClassifierEmptyLevelKeepsAdvisory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"level":"","advisory":"fine"}`))
	}))
	t.Cleanup(srv.Close)
	clf, err := NewLocalClassifier(srv.URL, "m", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	e.SetClassifier(clf)
	d := e.Evaluate(context.Background(), bashReq("bot", "sess", "task", "/work", "git status"))
	if d.Level != LevelLow || d.Verdict == VerdictAllow {
		t.Fatalf("%+v", d)
	}
	for _, item := range e.ListPending() {
		if item.ID == d.PendingID {
			if item.Advisory.Text != "fine" || item.Advisory.Source != "table" || !item.Advisory.Checked {
				t.Fatalf("%+v", item.Advisory)
			}
			return
		}
	}
	t.Fatal("no card")
}
