package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestRefusedBindAudit(t *testing.T) {
	dir := t.TempDir()
	if err := chmodDataDir(dir); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.log")
	policyPath := filepath.Join(dir, "policy.toml")
	body := "[security]\naudit_log = " + strconv.Quote(auditPath) + "\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	const canary = "CANARY-SECRET-BYTES"
	if err := os.WriteFile(filepath.Join(ssh, "id_ed25519"), []byte(canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := New(config.Config{
		DataDir: dir, BindAddr: "127.0.0.1:0",
		OllamaURL: "http://127.0.0.1:9", Model: "test-model", Version: "0.1.0",
		PolicyPath: policyPath,
		BuildBinds: []string{ssh},
	}, fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
		return model.ChatResponse{Content: "no"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	app.noGrokProxy = true
	t.Cleanup(app.Shutdown)
	srv := serve(t, app)

	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]any{
		"name": "Builder", "description": "stay", "grants": []string{"build"},
	}, "")
	if res.StatusCode != 200 && res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot store.Bot
	decodeJSON(t, b, &bot)
	if !strings.Contains(strings.Join(bot.Grants, ","), "build") {
		t.Fatalf("grants %v", bot.Grants)
	}
	out, err := app.dispatchTool(context.Background(), bot, "run_shell", map[string]any{"command": "true"})
	if err != nil && !strings.Contains(out, "stdout:") {
		t.Fatalf("shell: %v\n%s", err, out)
	}

	raw := readAudit(t, auditPath)
	if strings.Contains(raw, canary) {
		t.Fatalf("audit leaked file contents:\n%s", raw)
	}
	var found map[string]any
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" || !strings.Contains(line, "sandbox_block") {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("row %q: %v", line, err)
		}
		detail, _ := row["detail"].(string)
		if row["action"] == "sandbox_block" && strings.Contains(detail, "refused bind "+ssh) {
			found = row
			break
		}
	}
	if found == nil {
		t.Fatalf("audit missing refused bind:\n%s\nshell:\n%s", raw, out)
	}
	if found["bot_id"] != bot.ID {
		t.Fatalf("bot id %#v", found)
	}
	detail, _ := found["detail"].(string)
	if strings.Contains(detail, canary) {
		t.Fatalf("detail leaked %q", detail)
	}
	logged := logDetails(t, srv.URL, "sandbox_block")
	saw := false
	for _, row := range logged {
		d, _ := row["detail"].(string)
		if strings.Contains(d, "refused bind "+ssh) {
			saw = true
		}
		if strings.Contains(d, canary) {
			t.Fatalf("event log leaked %v", row)
		}
	}
	if !saw {
		t.Fatalf("event log %#v", logged)
	}
}
