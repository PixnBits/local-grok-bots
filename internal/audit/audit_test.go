package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
