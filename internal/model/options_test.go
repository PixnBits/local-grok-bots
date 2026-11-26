package model

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatOptionsJSON(t *testing.T) {
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, b)
		w.Header().Set("Content-Type", "application/x-ndjson")
		f := w.(http.Flusher)
		writeNDJSON(w, f, map[string]any{
			"message": map[string]any{"role": "assistant", "content": "ok"},
			"done":    true,
		})
	}))
	defer srv.Close()
	o := NewOllama(srv.URL)
	yes := true
	no := false
	reqs := []ChatRequest{
		{Model: "m"},
		{Model: "m", Think: &yes},
		{Model: "m", Think: &no},
		{Model: "m", NumCtx: 4096},
	}
	for _, req := range reqs {
		if _, err := o.Chat(context.Background(), req, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(bodies) != 4 {
		t.Fatalf("bodies %d", len(bodies))
	}
	assertAbsent := func(i int, key string) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(bodies[i], &m); err != nil {
			t.Fatal(err)
		}
		if _, ok := m[key]; ok {
			t.Fatalf("body %d has %s: %s", i, key, bodies[i])
		}
	}
	assertAbsent(0, "think")
	if opts, ok := unmarshalMap(t, bodies[0])["options"]; ok {
		if _, has := opts.(map[string]any)["num_ctx"]; has {
			t.Fatalf("unset num_ctx: %s", bodies[0])
		}
	}
	var on map[string]any
	if err := json.Unmarshal(bodies[1], &on); err != nil {
		t.Fatal(err)
	}
	if on["think"] != true {
		t.Fatalf("think true: %s", bodies[1])
	}
	var off map[string]any
	if err := json.Unmarshal(bodies[2], &off); err != nil {
		t.Fatal(err)
	}
	if off["think"] != false {
		t.Fatalf("think false omitted or not false: %s", bodies[2])
	}
	if !strings.Contains(string(bodies[2]), `"think":false`) {
		t.Fatalf("think false encoding: %s", bodies[2])
	}
	var ctx map[string]any
	if err := json.Unmarshal(bodies[3], &ctx); err != nil {
		t.Fatal(err)
	}
	opts, _ := ctx["options"].(map[string]any)
	if opts["num_ctx"] != float64(4096) {
		t.Fatalf("num_ctx: %s", bodies[3])
	}
}

func unmarshalMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
