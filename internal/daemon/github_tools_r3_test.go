package daemon

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestNextOffsetIsTheMinimum(t *testing.T) {
	s := strings.Repeat("a", 4095) + "é" + "TAIL"
	payload := map[string]any{
		"body":  strings.Repeat("B", 5000),
		"files": []any{map[string]any{"patch": s}},
	}
	next, cut := windowGitHubFields(payload, 0, 4096)
	if !cut || next != 4095 {
		t.Fatalf("next %d cut %v", next, cut)
	}
}

func TestFitGitHubReadKeepsSummary(t *testing.T) {
	for _, fill := range []string{"\x01", `"`} {
		text := fitGitHubRead(heavyReadPayload(fill), 1, false, 0)
		if strings.Contains(text, `"omitted":true`) || !strings.Contains(text, "check-keep") || !strings.Contains(text, `"combined_state":"success"`) || !strings.Contains(text, `"count":9`) || len(text) > githubSizeCapBytes {
			t.Fatalf("fill %q len %d", fill, len(text))
		}
		if !strings.Contains(text, "legacy-keep") {
			t.Fatal("statuses dropped")
		}
	}
}

func TestFitGitHubReadWindowsNames(t *testing.T) {
	fill := strings.Repeat("\x01", 4000)
	files := make([]any, 9)
	notes := make([]any, 9)
	for i := 0; i < 9; i++ {
		files[i] = map[string]any{"filename": fill, "patch": "p"}
		notes[i] = map[string]any{"path": fill, "body": "n", "diff_hunk": "h"}
	}
	payload := map[string]any{
		"files":           files,
		"review_comments": notes,
		"checks":          []any{map[string]any{"name": "check-keep", "conclusion": "success"}},
		"statuses":        []any{map[string]any{"name": "legacy-keep", "conclusion": "success"}},
		"combined_state":  "success",
		"count":           9,
	}
	text := fitGitHubRead(payload, 1, false, 0)
	if strings.Contains(text, `"omitted":true`) {
		t.Fatal("names fell through to a silent summary")
	}
	if !strings.Contains(text, "check-keep") || !strings.Contains(text, `"combined_state":"success"`) || !strings.Contains(text, `"count":9`) {
		t.Fatal("summary dropped")
	}
	var got map[string]any
	if json.Unmarshal([]byte(text), &got) != nil {
		t.Fatal("json")
	}
	if _, ok := got["next_offset"]; !ok {
		if _, named := got["filename_next"]; !named {
			if _, pathNext := got["path_next"]; !pathNext {
				t.Fatal("no continuation")
			}
		}
	}
	if len(text) > githubSizeCapBytes {
		t.Fatalf("len %d", len(text))
	}
}

func TestFitGitHubReadSummaryFallback(t *testing.T) {
	payload := heavyReadPayload("\x01")
	for i := 0; i < 80; i++ {
		payload["extra"+strconv.Itoa(i)] = strings.Repeat("\x01", 2000)
	}
	text := fitGitHubRead(payload, 1, false, 0)
	if !strings.Contains(text, `"omitted":true`) {
		t.Fatal("missing omitted")
	}
	if !strings.Contains(text, "check-keep") || !strings.Contains(text, `"combined_state":"success"`) || !strings.Contains(text, `"count":9`) || !strings.Contains(text, "legacy-keep") {
		t.Fatal("summary dropped")
	}
	var got map[string]any
	if json.Unmarshal([]byte(text), &got) != nil {
		t.Fatal("json")
	}
	if _, ok := got["next_offset"]; ok {
		t.Fatalf("decoy next %v", got["next_offset"])
	}
	if _, ok := got["next_page"]; ok {
		t.Fatalf("decoy page %v", got["next_page"])
	}
	if got["truncated"] != true {
		t.Fatal("truncated")
	}
	if _, ok := got["body"]; ok || got["files"] != nil {
		t.Fatal("slim still has body fields")
	}
	if len(text) > githubSizeCapBytes {
		t.Fatalf("len %d", len(text))
	}
}

func TestFitGitHubReadContinues(t *testing.T) {
	text := fitGitHubRead(heavyReadPayload("\x01"), 1, false, 0)
	var got map[string]any
	if json.Unmarshal([]byte(text), &got) != nil || strings.Contains(text, `"omitted":true`) {
		t.Fatalf("json len %d", len(text))
	}
	next, _ := got["next_offset"].(float64)
	if next <= 0 {
		t.Fatalf("next %v", next)
	}
	again := fitGitHubRead(heavyReadPayload("\x01"), 1, false, int(next))
	if strings.Contains(again, `"omitted":true`) || !strings.Contains(again, "check-keep") || !strings.Contains(again, `"combined_state":"success"`) {
		t.Fatal("continuation dropped the summary")
	}
	var more map[string]any
	if json.Unmarshal([]byte(again), &more) != nil {
		t.Fatal("continuation json")
	}
	second, _ := more["next_offset"].(float64)
	if second != 0 && second <= next {
		t.Fatalf("second %v first %v", second, next)
	}
}

func heavyReadPayload(fill string) map[string]any {
	chunk := strings.Repeat(fill, 4096)
	files := make([]any, 9)
	reviews := make([]any, 9)
	notes := make([]any, 9)
	talk := make([]any, 9)
	for i := 0; i < 9; i++ {
		files[i] = map[string]any{"filename": "f.go", "patch": chunk}
		reviews[i] = map[string]any{"body": chunk}
		notes[i] = map[string]any{"body": chunk, "diff_hunk": chunk}
		talk[i] = map[string]any{"body": chunk}
	}
	return map[string]any{
		"body":            chunk,
		"files":           files,
		"reviews":         reviews,
		"review_comments": notes,
		"conversation":    talk,
		"checks":          []any{map[string]any{"name": "check-keep", "conclusion": "success"}},
		"statuses":        []any{map[string]any{"name": "legacy-keep", "conclusion": "success"}},
		"combined_state":  "success",
		"count":           9,
	}
}

func TestReadPRContinuationKeepsIdentifiers(t *testing.T) {
	unit := strings.Repeat("a", 40) + "é日\n"
	var raw strings.Builder
	for raw.Len() <= 11029 {
		raw.WriteString(unit)
	}
	patch := raw.String()
	if len(patch) <= 11029 || !strings.Contains(patch, "é") || !strings.Contains(patch, "日") {
		t.Fatalf("patch %d", len(patch))
	}
	const (
		title    = "Tiếng Việt"
		file     = "h/handler13.go"
		path     = "internal/daemon/github_tools.go"
		author   = "alice"
		talkUser = "bea"
		name     = "alice"
	)
	payload := func() map[string]any {
		return map[string]any{
			"title": title,
			"body":  "short",
			"files": []any{map[string]any{
				"filename": file, "patch": patch, "status": "modified",
			}},
			"reviews": []any{map[string]any{"user": author, "name": name, "state": "APPROVED", "body": "LGTM"}},
			"review_comments": []any{map[string]any{
				"user": author, "path": path, "body": "nit", "diff_hunk": "@@",
			}},
			"conversation":   []any{map[string]any{"user": talkUser, "body": "hello"}},
			"checks":         []any{map[string]any{"name": "check-keep", "conclusion": "success"}},
			"combined_state": "success",
			"count":          1,
		}
	}
	var got strings.Builder
	offset := 0
	pages := 0
	for pages < 20 {
		text := fitGitHubRead(payload(), 1, false, offset)
		var parsed map[string]any
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed["title"] != title {
			t.Fatalf("page %d title %#v", pages, parsed["title"])
		}
		files, _ := parsed["files"].([]any)
		if len(files) != 1 {
			t.Fatalf("page %d files %#v", pages, parsed["files"])
		}
		f, _ := files[0].(map[string]any)
		if f["filename"] != file {
			t.Fatalf("page %d filename %#v offset %d", pages, f["filename"], offset)
		}
		chunk, _ := f["patch"].(string)
		got.WriteString(chunk)
		notes, _ := parsed["review_comments"].([]any)
		n, _ := notes[0].(map[string]any)
		if n["path"] != path || n["user"] != author {
			t.Fatalf("page %d note %#v", pages, n)
		}
		reviews, _ := parsed["reviews"].([]any)
		rv, _ := reviews[0].(map[string]any)
		if rv["user"] != author || rv["name"] != name {
			t.Fatalf("page %d review %#v", pages, rv)
		}
		talk, _ := parsed["conversation"].([]any)
		cv, _ := talk[0].(map[string]any)
		if cv["user"] != talkUser {
			t.Fatalf("page %d author %#v", pages, cv["user"])
		}
		pages++
		next, _ := parsed["next_offset"].(float64)
		if next == 0 {
			break
		}
		if int(next) <= offset {
			t.Fatalf("stuck offset %d next %v", offset, next)
		}
		offset = int(next)
	}
	if pages < 2 || offset == 0 {
		t.Fatalf("pages %d offset %d", pages, offset)
	}
	if got.String() != patch {
		t.Fatalf("rebuild %d want %d", got.Len(), len(patch))
	}
}

func TestProxyCfgNilBeforePolicy(t *testing.T) {
	b, err := os.ReadFile("github.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func (a *App) openGitHubProxyCfg")
	if i < 0 {
		t.Fatal("missing openGitHubProxyCfg")
	}
	rest := src[i:]
	if j := strings.Index(rest[1:], "\nfunc "); j >= 0 {
		rest = rest[:j+1]
	}
	nilAt := strings.Index(rest, "a == nil")
	polAt := strings.Index(rest, "a.effPol")
	if nilAt < 0 || polAt < 0 || nilAt > polAt {
		t.Fatalf("nil %d policy %d", nilAt, polAt)
	}
	var app *App
	px, err := app.openGitHubProxyCfg(store.Bot{}, false)
	if px != nil || err != nil {
		t.Fatalf("nil app %v %v", px, err)
	}
}
