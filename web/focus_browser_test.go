package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFocusBrowser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("skip: node is not installed")
	}
	pw := os.Getenv("LGB_PLAYWRIGHT_DIR")
	if pw == "" {
		pw = "/home/pixnbits/lgb-dev-data/shotkit/node_modules/playwright"
	}
	if st, err := os.Stat(pw); err != nil || !st.IsDir() {
		t.Skip("skip: playwright is missing at " + pw)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	chrome := filepath.Join(home, ".cache", "ms-playwright", "chromium-1243", "chrome-linux64", "chrome")
	if st, err := os.Stat(chrome); err != nil || st.IsDir() {
		t.Skip("skip: chromium-1243 is missing at " + chrome)
	}
	script := filepath.Join("testdata", "focus_check.mjs")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newFocusServer())
	defer srv.Close()
	cmd := exec.Command(node, script, "--base", srv.URL)
	cmd.Env = append(os.Environ(), "LGB_PLAYWRIGHT_DIR="+pw, "LGB_CHROMIUM="+chrome)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("focus check failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "focus ok") {
		t.Fatalf("focus check output:\n%s", out)
	}
}

type focusState struct {
	mu      sync.Mutex
	pending []map[string]any
	rules   []map[string]any
	next    int
}

func newFocusServer() http.Handler {
	st := &focusState{next: 2}
	st.reset()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			writeBytes(w, "text/javascript; charset=utf-8", AppJS)
		case "/app.css":
			writeBytes(w, "text/css; charset=utf-8", AppCSS)
		case "/theme.js":
			writeBytes(w, "text/javascript; charset=utf-8", ThemeJS)
		case "/", "/index.html", "/rules":
			writeBytes(w, "text/html; charset=utf-8", IndexHTML)
		case "/__focus/reset":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			st.reset()
			writeJSON(w, map[string]any{"ok": true})
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") {
				st.api(w, r)
				return
			}
			http.NotFound(w, r)
		}
	})
	return mux
}

func (st *focusState) reset() {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	st.pending = []map[string]any{
		focusItem("p1", "/work/s1", now),
		focusItem("p2", "/work/s2", now),
	}
	st.rules = []map[string]any{focusRule("r1", now)}
	st.next = 2
}

func focusItem(id, cwd, now string) map[string]any {
	return map[string]any{
		"id": id, "level": "low", "bot_id": "b1", "bot_name": "Ada",
		"tool": "run_shell", "argv": []string{"echo", "hi"}, "cwd": cwd,
		"created_at": now, "allowed_scopes": []string{"once", "task", "bot", "global"},
		"compound": false,
	}
}

func focusRule(id, now string) map[string]any {
	return map[string]any{
		"id": id, "effect": "allow", "argv": []string{"echo", "hi"},
		"tool": "shell", "scope": "global", "bot_id": "", "created_at": now,
		"kind": "exact", "pattern": "", "source": "api",
	}
}

func (st *focusState) api(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/health":
		writeJSON(w, map[string]any{"status": "ok", "version": "test"})
	case path == "/api/bots":
		writeJSON(w, []any{map[string]any{
			"id": "b1", "name": "Ada", "label": "helper", "status": "idle",
			"archived": false, "hidden": false, "pinned": false,
			"mark": map[string]any{"shape": "circle", "color": "#4C77DD"},
		}})
	case path == "/api/permbroker/pending":
		st.mu.Lock()
		items := append([]map[string]any{}, st.pending...)
		st.mu.Unlock()
		writeJSON(w, map[string]any{"pending": items})
	case path == "/api/permbroker/pending/approve-all" || path == "/api/permbroker/pending/deny-all":
		var body struct {
			IDs []string `json:"ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		st.drop(body.IDs)
		writeJSON(w, map[string]any{"ok": true})
	case path == "/api/permbroker/rules" && r.Method == http.MethodGet:
		st.mu.Lock()
		rules := append([]map[string]any{}, st.rules...)
		st.mu.Unlock()
		writeJSON(w, map[string]any{"rules": rules, "task_grants": []any{}})
	case path == "/api/permbroker/rules" && r.Method == http.MethodPost:
		st.mu.Lock()
		st.next++
		id := fmt.Sprintf("r%d", st.next)
		now := time.Now().UTC().Format(time.RFC3339)
		rule := focusRule(id, now)
		st.rules = append(st.rules, rule)
		st.mu.Unlock()
		writeJSON(w, map[string]any{"rule": rule})
	case strings.HasPrefix(path, "/api/permbroker/rules/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(path, "/api/permbroker/rules/")
		st.mu.Lock()
		next := st.rules[:0]
		for _, rule := range st.rules {
			if rule["id"] != id {
				next = append(next, rule)
			}
		}
		st.rules = next
		st.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true})
	case path == "/api/permbroker/recent":
		writeJSON(w, map[string]any{"recent": []any{}})
	case path == "/api/permbroker/risk-tables":
		writeJSON(w, map[string]any{"builtin": []any{}, "stricter": []any{}})
	case path == "/api/permbroker/patterns/wrappers":
		writeJSON(w, map[string]any{"wrappers": []any{}})
	default:
		writeJSON(w, map[string]any{})
	}
}

func (st *focusState) drop(ids []string) {
	gone := map[string]bool{}
	for _, id := range ids {
		gone[id] = true
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	next := st.pending[:0]
	for _, item := range st.pending {
		id, _ := item["id"].(string)
		if !gone[id] {
			next = append(next, item)
		}
	}
	st.pending = next
}

func writeBytes(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
