package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
)

// logDetailShape is a stand-in for a typed log payload. Hidden must not be
// stored: json.Marshal honors the "-" tag.
type logDetailShape struct {
	Note   string `json:"note"`
	Tokens int    `json:"tokens"`
	Hidden string `json:"-"`
}

type logStringer struct {
	text string
}

func (s logStringer) String() string { return s.text }

func TestModelCallLogHidesTokens(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("A1b2", 9)
	ant := "sk-" + "ant-" + strings.Repeat("a1", 8)
	app := newApp(t, t.TempDir(), fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	callErr := fmt.Errorf("upstream rejected %s and %s", ghp, ant)
	app.logOllamaCall(bot.ID, "test-model", false, 1, false, 0, callErr, 0, "", "", nil)

	raw := map[string]any{
		"error": ghp + " " + ant,
		"nested": map[string]any{
			"note": ant,
			"list": []any{ghp},
		},
		"names": []string{ant},
	}
	app.log(bot.ID, "model_call", raw)
	if raw["error"] != ghp+" "+ant {
		t.Fatal("caller map was modified")
	}
	nested := raw["nested"].(map[string]any)
	if nested["note"] != ant || nested["list"].([]any)[0] != ghp || raw["names"].([]string)[0] != ant {
		t.Fatal("caller map was modified")
	}

	events, err := app.st.ListLog(bot.ID, "model_call", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("model_call rows %d", len(events))
	}
	var sawOllama bool
	for _, ev := range events {
		body := string(ev.Detail)
		if strings.Contains(body, ghp) || strings.Contains(body, ant) {
			t.Fatalf("stored row leaked %s", body)
		}
		var detail map[string]any
		if err := json.Unmarshal(ev.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		errText, ok := detail["error"].(string)
		if !ok || errText == "" {
			t.Fatalf("missing error field %s", body)
		}
		if !strings.Contains(errText, "[redacted]") {
			t.Fatalf("error not redacted %q", errText)
		}
		if detail["model"] == "test-model" {
			sawOllama = true
			if !strings.Contains(errText, "upstream rejected") {
				t.Fatalf("ollama error %q", errText)
			}
		}
	}
	if !sawOllama {
		t.Fatal("model_call row from logOllamaCall missing")
	}

	srv := serve(t, app)
	res, body := do(t, "GET", srv.URL+"/api/log?kind=model_call&limit=20", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("status %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), ghp) || strings.Contains(string(body), ant) {
		t.Fatalf("GET /api/log leaked %s", body)
	}
	var listed []store.LogEvent
	decodeJSON(t, body, &listed)
	if len(listed) != 2 {
		t.Fatalf("api rows %d %s", len(listed), body)
	}
}

func TestLogDetailRedactsEveryShape(t *testing.T) {
	token := "ghp_" + strings.Repeat("A1b2", 9)
	notice := "notice " + token
	tokenB64 := base64.StdEncoding.EncodeToString([]byte(token))
	app := newApp(t, t.TempDir(), fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	srv := serve(t, app)

	type shapeRow struct {
		name       string
		detail     any
		after      func(t *testing.T)
		word       string
		structJSON bool
		rawBytes   []byte
	}
	shape := func(note string) logDetailShape {
		return logDetailShape{Note: note, Tokens: 42, Hidden: "hidden-marker"}
	}

	text := []string{notice, "kept"}
	items := []any{notice, "kept"}
	inner := map[string]any{"note": notice}
	nested := map[string]any{"inner": inner, "plain": "kept"}
	pairs := map[string]string{"note": notice, "plain": "kept"}
	errVal := fmt.Errorf("notice %s", token)
	stringer := logStringer{text: notice}
	structVal := shape(notice)
	structMap := map[string]any{"v": structVal}
	structPtr := shape(notice)
	ptrMap := map[string]any{"v": &structPtr}
	str := notice
	strPtr := &str
	strMap := map[string]any{"v": strPtr}
	raw := json.RawMessage(`{"note":"` + notice + `","plain":"kept"}`)
	rawMap := map[string]any{"v": raw}
	buf := []byte(notice)
	bufMap := map[string]any{"v": buf}
	labels := []string{notice, "kept"}
	labelMap := map[string][]string{"labels": labels}
	elem := map[string]any{"note": notice}
	mapList := []map[string]any{elem, {"plain": "kept"}}
	keyMap := map[string]any{token: "kept"}
	keyInts := map[string]int{token: 7}
	whole := shape(notice)

	rows := []shapeRow{
		{name: "string", detail: notice, word: "notice"},
		{name: "strings", detail: text, word: "kept", after: func(t *testing.T) {
			if text[0] != notice || text[1] != "kept" {
				t.Fatal("caller []string mutated")
			}
		}},
		{name: "any_list", detail: items, word: "kept", after: func(t *testing.T) {
			if items[0] != notice || items[1] != "kept" {
				t.Fatal("caller []any mutated")
			}
		}},
		{name: "nested_map", detail: nested, word: "kept", after: func(t *testing.T) {
			if inner["note"] != notice || nested["plain"] != "kept" {
				t.Fatal("caller map mutated")
			}
		}},
		{name: "string_map", detail: pairs, word: "kept", after: func(t *testing.T) {
			if pairs["note"] != notice || pairs["plain"] != "kept" {
				t.Fatal("caller map[string]string mutated")
			}
		}},
		{name: "error", detail: map[string]any{"v": errVal}, word: "notice"},
		{name: "stringer", detail: map[string]any{"v": stringer}, word: "notice"},
		{name: "struct", detail: structMap, word: "notice", structJSON: true, after: func(t *testing.T) {
			if structVal.Note != notice || structVal.Tokens != 42 || structVal.Hidden != "hidden-marker" {
				t.Fatal("caller struct mutated")
			}
			if structMap["v"].(logDetailShape) != structVal {
				t.Fatal("caller map mutated")
			}
		}},
		{name: "struct_ptr", detail: ptrMap, word: "notice", structJSON: true, after: func(t *testing.T) {
			if structPtr.Note != notice || structPtr.Tokens != 42 || structPtr.Hidden != "hidden-marker" {
				t.Fatal("caller struct pointer mutated")
			}
			if ptrMap["v"] != &structPtr {
				t.Fatal("caller map mutated")
			}
		}},
		{name: "string_ptr", detail: strMap, word: "notice", after: func(t *testing.T) {
			if *strPtr != notice || strMap["v"] != strPtr {
				t.Fatal("caller *string mutated")
			}
		}},
		{name: "raw_json", detail: rawMap, word: "kept", after: func(t *testing.T) {
			if !strings.Contains(string(raw), token) || rawMap["v"].(json.RawMessage) == nil {
				t.Fatal("caller RawMessage mutated")
			}
		}},
		{name: "bytes", detail: bufMap, rawBytes: buf, after: func(t *testing.T) {
			if string(buf) != notice || len(bufMap["v"].([]byte)) != len(notice) {
				t.Fatal("caller []byte mutated")
			}
		}},
		{name: "string_lists", detail: labelMap, word: "kept", after: func(t *testing.T) {
			if labels[0] != notice || labelMap["labels"][0] != notice {
				t.Fatal("caller map[string][]string mutated")
			}
		}},
		{name: "map_list", detail: mapList, word: "kept", after: func(t *testing.T) {
			if elem["note"] != notice || mapList[0]["note"] != notice {
				t.Fatal("caller []map[string]any mutated")
			}
		}},
		{name: "map_key", detail: keyMap, word: "kept", after: func(t *testing.T) {
			if keyMap[token] != "kept" || len(keyMap) != 1 {
				t.Fatal("caller map key mutated")
			}
		}},
		{name: "map_key_int", detail: keyInts, after: func(t *testing.T) {
			if keyInts[token] != 7 || len(keyInts) != 1 {
				t.Fatal("caller map[string]int mutated")
			}
		}},
		{name: "whole_struct", detail: whole, word: "notice", structJSON: true, after: func(t *testing.T) {
			if whole.Note != notice || whole.Tokens != 42 || whole.Hidden != "hidden-marker" {
				t.Fatal("caller whole struct mutated")
			}
		}},
	}
	if len(rows) != 17 {
		t.Fatalf("shape rows %d", len(rows))
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			kind := "shape_" + row.name
			app.log(bot.ID, kind, row.detail)
			if row.after != nil {
				row.after(t)
			}
			events, err := app.st.ListLog(bot.ID, kind, "", 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 {
				t.Fatalf("stored rows %d", len(events))
			}
			stored := string(events[0].Detail)
			res, body := do(t, "GET", srv.URL+"/api/log?kind="+kind+"&limit=20", nil, "")
			if res.StatusCode != 200 {
				t.Fatalf("status %d %s", res.StatusCode, body)
			}
			api := string(body)
			if strings.Contains(stored, token) || strings.Contains(api, token) {
				t.Fatalf("leaked stored=%s api=%s", stored, api)
			}
			if row.word != "" && (!strings.Contains(stored, row.word) || !strings.Contains(stored, "[redacted]")) {
				t.Fatalf("stored %s", stored)
			}
			if row.name == "error" || row.name == "stringer" {
				if !strings.Contains(stored, "notice") || !strings.Contains(stored, "[redacted]") || strings.Contains(stored, "{}") {
					t.Fatalf("lost value %s", stored)
				}
			}
			if row.structJSON {
				if !strings.Contains(stored, `"tokens":42`) || strings.Contains(stored, "hidden-marker") {
					t.Fatalf("struct %s", stored)
				}
			}
			if row.name == "map_key_int" {
				var got map[string]float64
				if err := json.Unmarshal(events[0].Detail, &got); err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 || got["[redacted]"] != 7 || strings.Contains(stored, token) {
					t.Fatalf("int key %s", stored)
				}
			}
			if row.rawBytes != nil {
				if strings.Contains(stored, tokenB64) || strings.Contains(api, tokenB64) {
					t.Fatalf("base64 leaked stored=%s api=%s", stored, api)
				}
				var wrap struct {
					V []byte `json:"v"`
				}
				if err := json.Unmarshal(events[0].Detail, &wrap); err != nil {
					t.Fatal(err)
				}
				decoded := string(wrap.V)
				if strings.Contains(decoded, token) || !strings.Contains(decoded, "notice [redacted]") {
					t.Fatalf("decoded %q", decoded)
				}
			}
		})
	}
}
