package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFileSinkRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(map[string]any{"event": "cli_start", "session_id": "s", "note": "ANTHROPIC_API_KEY=abcd"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"event":"cli_start"`) || strings.Contains(string(b), "abcd") {
		t.Fatalf("audit %s", b)
	}
}

func TestRedactValueHidesKeysAndTokens(t *testing.T) {
	got := RedactValue(map[string]any{
		"command": "echo sk-supersecretvalue12",
		"api_key": "sk-supersecretvalue12",
		"nested":  []any{"ghp_abcdefghijklmnop"},
	}).(map[string]any)
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "sk-supersecretvalue12") || strings.Contains(string(b), "ghp_abcdefghijklmnop") {
		t.Fatalf("secret leaked: %s", b)
	}
	if got["api_key"] != "[redacted]" {
		t.Fatalf("key %#v", got["api_key"])
	}
	named := RedactValue(map[string]any{
		"token_name": "alice",
		"token":      "abcdefghijklmnopqrstuvwxyz012345",
	}).(map[string]any)
	if named["token_name"] != "alice" || named["token"] != "[redacted]" {
		t.Fatalf("token_name %#v", named)
	}
	digest := strings.Repeat("ab", 32)
	kept := RedactDetail(map[string]any{
		"body_sha256": digest,
		"token":       digest,
	}).(map[string]any)
	if kept["body_sha256"] != digest || kept["token"] != "[redacted]" {
		t.Fatalf("digest %#v", kept)
	}
}

// Real-shaped fakes. Lengths follow the formats this daemon handles:
// Anthropic bodies include hyphen and underscore segments, xAI is xai- plus
// 20 or more alphanumerics, lgbr_ and the admin token are 32 bytes of hex.
func fakeSecrets() (ant, oat, adminKey, xai, ghp, ghPat, lgbr, adminTok, openai, bearer string) {
	ant = "sk-ant-api03-abc123xyz-456def789ghij_klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA"
	oat = "sk-ant-oat01-ZYXwvutsrqponmlkjihgf_edcba9876543210-ABCDEFGhijKLMNOpqRSTUVwxyAA"
	adminKey = "sk-ant-admin01-abc123xyz-456def789ghij_klmnopqrstuvwx-3456yza789bcde-adminTOKEnAA"
	xai = "xai-" + strings.Repeat("ab12cd34", 5)
	ghp = "ghp_" + strings.Repeat("A1b2", 9)
	ghPat = "github_pat_11AABBCCDDEEFF00112233_0123456789abcdef0123456789abcdef0123456789a"
	lgbr = "lgbr_" + strings.Repeat("ab", 32)
	adminTok = strings.Repeat("cd", 32)
	openai = "sk-" + strings.Repeat("a1", 24)
	bearer = "Bearer ya29.a0AfH6SMC_fake-token~value/extra"
	return
}

func TestRedactTextCatchesRealShapes(t *testing.T) {
	ant, oat, adminKey, xai, ghp, ghPat, lgbr, adminTok, openai, bearer := fakeSecrets()
	shortHex := strings.Repeat("ef", 31) // 62 hex chars, not an admin token
	longHex := strings.Repeat("ab", 33)  // 66 hex chars, no 64-hex boundary
	for _, secret := range []string{ant, oat, adminKey, xai, ghp, ghPat, lgbr, adminTok, openai, bearer, "sk-supersecretvalue12"} {
		got := RedactText("before " + secret + " after")
		if strings.Contains(got, secret) || got != "before [redacted] after" {
			t.Fatalf("%s -> %s", secret, got)
		}
	}
	kept := RedactText("sk-test xai-short " + shortHex + " " + longHex + " sk-ant-nope")
	for _, plain := range []string{"sk-test", "xai-short", shortHex, longHex, "sk-ant-nope"} {
		if !strings.Contains(kept, plain) {
			t.Fatalf("over-redacted %q in %s", plain, kept)
		}
	}
	if strings.Contains(kept, "[redacted]") {
		t.Fatalf("plain text redacted: %s", kept)
	}
	assigned := RedactText("ANTHROPIC_API_KEY=" + ant)
	if strings.Contains(assigned, ant) || !strings.Contains(assigned, "ANTHROPIC_API_KEY=redacted") {
		t.Fatalf("assignment %s", assigned)
	}
}

func TestRedactValueWalksNestedValuesAndKeepsJSONTypes(t *testing.T) {
	ant, _, _, xai, _, _, lgbr, adminTok, _, _ := fakeSecrets()
	got := RedactValue(map[string]any{
		"multiSelect": false,
		"count":       2,
		"ratio":       1.5,
		"note":        nil,
		"n":           json.Number("3"),
		"questions": []any{
			map[string]any{
				"question":    "use " + ant,
				"multiSelect": true,
				"nested": map[string]string{
					"xai": xai,
				},
				"files": []string{"/tmp/" + adminTok, "ok"},
			},
		},
		"err":   fmt.Errorf("cli failed: %s", lgbr),
		"items": []any{fmt.Errorf("also %s", xai), false, 4},
	}).(map[string]any)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, secret := range []string{ant, xai, lgbr, adminTok} {
		if strings.Contains(body, secret) {
			t.Fatalf("leaked %s in %s", secret, body)
		}
	}
	for _, want := range []string{`"multiSelect":false`, `"multiSelect":true`, `"count":2`, `"ratio":1.5`, `"note":null`, `"n":3`, `"ok"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	for _, bad := range []string{`"multiSelect":"false"`, `"multiSelect":"true"`, `"count":"2"`, `"note":"<nil>"`} {
		if strings.Contains(body, bad) {
			t.Fatalf("stringified %s in %s", bad, body)
		}
	}
	if got["multiSelect"] != false || got["count"] != 2 || got["ratio"] != 1.5 || got["note"] != nil {
		t.Fatalf("types %#v", got)
	}
	if _, ok := got["n"].(json.Number); !ok {
		t.Fatalf("number type %T", got["n"])
	}
	errText, _ := got["err"].(string)
	if !strings.Contains(errText, "[redacted]") || !strings.Contains(errText, "cli failed") {
		t.Fatalf("error %q", errText)
	}
	long := strings.Repeat("a", 600)
	clipped := RedactValue(long).(string)
	if strings.Contains(clipped, strings.Repeat("a", 501)) || !strings.HasSuffix(clipped, "…(truncated)") {
		t.Fatalf("clip %q", clipped)
	}
}

func TestWriteRedactsNestedSecretsWithoutClipping(t *testing.T) {
	ant, _, _, xai, _, _, lgbr, adminTok, _, _ := fakeSecrets()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	note := strings.Repeat("n", 600)
	l.Write(map[string]any{
		"event": "model_call",
		"ok":    false,
		"pid":   7,
		"error": "boom " + ant,
		"nested": map[string]any{
			"err":   fmt.Errorf("stderr %s", xai),
			"files": []string{lgbr, "plain"},
			"deep":  map[string]any{"admin": adminTok, "flag": true},
		},
		"note": note,
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, secret := range []string{ant, xai, lgbr, adminTok} {
		if strings.Contains(body, secret) {
			t.Fatalf("leaked %s in %s", secret, body)
		}
	}
	for _, want := range []string{`"ok":false`, `"pid":7`, `"flag":true`, note, "[redacted]", "boom ", "stderr ", "plain"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}
}

// TestRedactValueOutputUnchanged pins the behaviors RedactDetail must not
// take over: string clip, []byte passthrough, and numeric secret-key redaction.
func TestRedactValueOutputUnchanged(t *testing.T) {
	long := strings.Repeat("a", 600)
	got := RedactValue(long).(string)
	want := strings.Repeat("a", 500) + "…(truncated)"
	if got != want {
		t.Fatalf("clip %q", got)
	}

	tok := "ghp_" + strings.Repeat("A1b2", 9)
	b := []byte("prefix-" + tok)
	out := RedactValue(b).([]byte)
	if string(out) != string(b) || len(out) == 0 || &out[0] != &b[0] {
		t.Fatalf("[]byte passthrough got %q", out)
	}

	num := RedactValue(map[string]any{"tokens": 12}).(map[string]any)
	if num["tokens"] != "[redacted]" {
		t.Fatalf("numeric secret key %#v", num["tokens"])
	}
}

func TestRedactDetailKeepsScalars(t *testing.T) {
	tok := "ghp_" + strings.Repeat("A1b2", 9)
	other := "ghp_" + strings.Repeat("C3d4", 9)
	long := strings.Repeat("b", 600)
	if RedactDetail(long).(string) != long {
		t.Fatal("detail clipped a long string")
	}

	got := RedactDetail(map[string]any{
		"tokens":     12,
		"ok":         true,
		"note":       nil,
		"n":          json.Number("4"),
		"api_key":    "hello",
		"token_name": "alice",
	}).(map[string]any)
	if got["tokens"] != 12 || got["ok"] != true || got["note"] != nil || got["api_key"] != "[redacted]" || got["token_name"] != "alice" {
		t.Fatalf("scalars %#v", got)
	}
	if n, _ := got["n"].(json.Number); n != "4" {
		t.Fatalf("number %T %#v", got["n"], got["n"])
	}

	when := time.Date(2026, 11, 2, 3, 4, 5, 0, time.UTC)
	stamp, ok := RedactDetail(when).(string)
	if !ok || stamp != "2026-11-02T03:04:05Z" {
		t.Fatalf("time %T %q", RedactDetail(when), stamp)
	}

	keys := RedactDetail(map[string]any{
		tok:     "one",
		other:   "two",
		"plain": "kept",
	}).(map[string]any)
	if len(keys) != 3 || keys["[redacted]"] != "one" || keys["[redacted]#2"] != "two" || keys["plain"] != "kept" {
		t.Fatalf("keys %#v", keys)
	}
	if strings.Contains(fmt.Sprint(keys), tok) || strings.Contains(fmt.Sprint(keys), other) {
		t.Fatalf("key leaked %#v", keys)
	}
	if again := RedactDetail(keys); !reflect.DeepEqual(again, keys) {
		t.Fatalf("not idempotent %#v then %#v", keys, again)
	}

	raw := json.RawMessage("notice " + tok)
	text, ok := RedactDetail(raw).(string)
	if !ok || strings.Contains(text, tok) || text != "notice [redacted]" {
		t.Fatalf("invalid raw %T %q", RedactDetail(raw), text)
	}
	valid := json.RawMessage(`{"note":"notice ` + tok + `"}`)
	cleaned, ok := RedactDetail(valid).(json.RawMessage)
	if !ok || !json.Valid(cleaned) || strings.Contains(string(cleaned), tok) || !strings.Contains(string(cleaned), "notice [redacted]") {
		t.Fatalf("valid raw %s", cleaned)
	}

	buf := []byte("notice " + tok)
	red := RedactDetail(buf).([]byte)
	if string(buf) != "notice "+tok || strings.Contains(string(red), tok) || !strings.Contains(string(red), "notice [redacted]") {
		t.Fatalf("bytes %q caller %q", red, buf)
	}

	type hiddenChan struct {
		C chan int
	}
	if got := RedactDetail(hiddenChan{C: make(chan int)}); got != "[unencodable]" {
		t.Fatalf("unencodable %#v", got)
	}
}

func TestRedactDetailCycles(t *testing.T) {
	tok := "ghp_" + strings.Repeat("A1b2", 9)
	notice := "notice " + tok

	t.Run("map", func(t *testing.T) {
		m := map[string]any{"note": notice}
		m["self"] = m
		body := redactQuick(t, tok, m)
		if !strings.Contains(body, "[cycle]") || !strings.Contains(body, "notice [redacted]") {
			t.Fatalf("cycle %s", body)
		}
		if m["note"] != notice || m["self"].(map[string]any)["note"] != notice {
			t.Fatal("caller map mutated")
		}
		valueBody := mustMarshalRedacted(t, tok, RedactValue(m))
		if !strings.Contains(valueBody, "[cycle]") || !strings.Contains(valueBody, "notice [redacted]") {
			t.Fatalf("RedactValue cycle %s", valueBody)
		}
	})

	t.Run("slice", func(t *testing.T) {
		s := make([]any, 2)
		s[0] = s
		s[1] = notice
		body := redactQuick(t, tok, s)
		if !strings.Contains(body, "[cycle]") || !strings.Contains(body, "notice [redacted]") {
			t.Fatalf("cycle %s", body)
		}
		if s[1] != notice {
			t.Fatal("caller slice mutated")
		}
	})

	t.Run("deep", func(t *testing.T) {
		root := map[string]any{"note": notice}
		leaf := map[string]any{"leaf": notice}
		var cur any = leaf
		for i := 0; i < 10000; i++ {
			cur = map[string]any{"down": cur}
		}
		root["deep"] = cur
		body := redactQuick(t, tok, root)
		if !strings.Contains(body, "[depth]") || !strings.Contains(body, "notice [redacted]") {
			t.Fatalf("deep %s", body)
		}
		if root["note"] != notice || leaf["leaf"] != notice {
			t.Fatal("caller deep value mutated")
		}
	})

	t.Run("shared", func(t *testing.T) {
		shared := map[string]any{"note": notice}
		out := RedactDetail(map[string]any{"a": shared, "b": shared}).(map[string]any)
		for _, key := range []string{"a", "b"} {
			child, _ := out[key].(map[string]any)
			if child["note"] != "notice [redacted]" {
				t.Fatalf("%s %#v", key, out[key])
			}
		}
		if shared["note"] != notice {
			t.Fatal("shared map mutated")
		}
	})

	t.Run("empty slices", func(t *testing.T) {
		body := mustMarshalRedacted(t, tok, RedactDetail([]any{[]any{}, []any{notice}}))
		if strings.Contains(body, "[cycle]") || !strings.Contains(body, "notice [redacted]") {
			t.Fatalf("empty slices %s", body)
		}
	})
}

func redactQuick(t *testing.T, tok string, v any) string {
	t.Helper()
	start := time.Now()
	out := RedactDetail(v)
	if time.Since(start) > time.Second {
		t.Fatalf("slow %s", time.Since(start))
	}
	return mustMarshalRedacted(t, tok, out)
}

func mustMarshalRedacted(t *testing.T, tok string, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v", err)
	}
	if strings.Contains(string(b), tok) {
		t.Fatalf("leaked %s", b)
	}
	return string(b)
}
