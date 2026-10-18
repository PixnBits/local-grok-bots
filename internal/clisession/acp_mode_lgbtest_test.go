//go:build lgbtest

package clisession

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReplaySessionChangedEndsTurn(t *testing.T) {
	if grokHostJail() {
		if _, err := exec.LookPath("bwrap"); err != nil {
			t.Skip(err)
		}
	}
	raw, err := os.ReadFile("/tmp/r7-wire/yolo-true-1.0.62.json")
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	if !strings.Contains(line, `"method":"_x.ai/sessions/changed"`) || !strings.Contains(line, `"yolo":true`) {
		t.Fatal("captured line")
	}
	replayEndsTurn(t, line)
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	params, _ := msg["params"].(map[string]any)
	upserted, _ := params["upserted"].([]any)
	entry, _ := upserted[0].(map[string]any)
	delete(entry, "yolo")
	missing, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	replayEndsTurn(t, string(missing))
	entry["yolo"] = "false"
	nonBool, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	replayEndsTurn(t, string(nonBool))
}

func replayEndsTurn(t *testing.T, line string) {
	t.Helper()
	dir := t.TempDir()
	bin := writeScript(t, dir, "agent.sh", `#!/bin/sh
case "$1" in
--version) echo grok 1.0.62; exit 0;;
esac
id_of() { printf '%s' "$1" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p'; }
reply() { awk -v line="$1" 'BEGIN{print line; fflush()}'; }
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":1}}"
IFS= read -r line || exit 1
id=$(id_of "$line")
reply "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"sessionId\":\"s\",\"modes\":{\"currentModeId\":\"default\"}}}"
printf '%s\n' "$NOTIFY_LINE"
while :; do sleep 1; done
`)
	failed := false
	hooks := quietACP()
	hooks.Fail = func(tool string, args map[string]any, reason string) {
		failed = true
		if tool != "acp" || !strings.Contains(reason, "permission mode") {
			t.Errorf("fail %s %s", tool, reason)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := (ExecRunner{}).Run(ctx, Spec{
		Backend: "grok", Bin: bin, Fresh: true, Prompt: "hi", Workspace: dir,
		Isolate: &Isolation{
			Home:        dir,
			GrokSandbox: GrokProfile,
			Env:         []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "NOTIFY_LINE=" + line},
		},
		ACP: hooks,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "acp host:") || !strings.Contains(err.Error(), "permission mode") {
		t.Fatalf("%v", err)
	}
	if !failed {
		t.Fatal("turn was not audited")
	}
}
