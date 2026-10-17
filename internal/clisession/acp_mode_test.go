package clisession

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSessionModeMustBeDefault(t *testing.T) {
	ok := map[string]any{"modes": map[string]any{"currentModeId": "default"}}
	if acpResultModeProblem(ok) != "" {
		t.Fatal(acpResultModeProblem(ok))
	}
	for _, bad := range []map[string]any{
		nil,
		{"modes": map[string]any{"currentModeId": "other"}},
		{"modes": map[string]any{}},
		{"yolo": true, "modes": map[string]any{"currentModeId": "default"}},
		{"modes": map[string]any{"currentModeId": "default"}, "configOptions": []any{map[string]any{"id": "yolo", "value": true}}},
	} {
		if acpResultModeProblem(bad) == "" {
			t.Fatalf("accepted %#v", bad)
		}
	}
	quiet := map[string]any{
		"modes":         map[string]any{"currentModeId": "default"},
		"yolo":          false,
		"configOptions": []any{map[string]any{"id": "yolo", "value": "false"}, map[string]any{"id": "model", "value": "m"}, map[string]any{"id": "screen_mode", "value": "wide"}},
	}
	if acpResultModeProblem(quiet) != "" {
		t.Fatal(acpResultModeProblem(quiet))
	}
}

func TestUpdateModeAndBypass(t *testing.T) {
	if acpUpdateModeProblem(map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "default"}) != "" {
		t.Fatal("default update")
	}
	if acpUpdateModeProblem(map[string]any{"sessionUpdate": "current_mode_update", "currentModeId": "other"}) == "" {
		t.Fatal("other mode")
	}
	if acpUpdateModeProblem(map[string]any{"sessionUpdate": "current_mode_update"}) == "" {
		t.Fatal("missing mode")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "config_option_update",
		"configOptions": []any{map[string]any{"id": "yolo", "value": false}},
	}) != "" {
		t.Fatal("yolo false")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "config_option_update",
		"id":            "permission_mode",
		"value":         "other",
	}) == "" {
		t.Fatal("mode option")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "_x.ai/sessions/changed",
		"info":          map[string]any{"mode": "default"},
	}) != "" {
		t.Fatal("changed default")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "_x.ai/sessions/changed",
		"info":          map[string]any{"yolo": true},
	}) == "" {
		t.Fatal("changed bypass")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "agent_message_chunk",
		"rawInput":      map[string]any{"mode": "other"},
	}) != "" {
		t.Fatal("raw input was scanned")
	}
	meta := map[string]any{"_meta": map[string]any{"_x.ai/session_notification": map[string]any{"yolo": true}}}
	if metaModeProblem(asMap(meta["_meta"])) == "" {
		t.Fatal("notification")
	}
	if metaModeProblem(map[string]any{"_x.ai/session_notification": map[string]any{"yolo": false}}) != "" {
		t.Fatal("notification false")
	}
}

func TestSlashPromptAndDenyText(t *testing.T) {
	if !SlashPrompt("  /status") || SlashPrompt("please /status") || SlashPrompt("  ") {
		t.Fatal("slash")
	}
	if !denyText("Denied by a rule") || !denyText("not allowed") || denyText("") || denyText("failed to open") {
		t.Fatal("deny text")
	}
	var noted string
	_, err := (ExecRunner{}).Run(context.Background(), Spec{
		Backend: "grok", Prompt: "\n/status", Workspace: t.TempDir(),
		ACP: &ACPHooks{
			Decide: func(context.Context, ACPAsk) (ACPDecision, error) { return ACPDecision{}, nil },
			Fail: func(tool string, args map[string]any, reason string) {
				noted = tool + " " + reason
			},
		},
	}, nil)
	if !errors.Is(err, ErrSlash) || !strings.Contains(noted, ErrSlash.Error()) {
		t.Fatalf("%v %s", err, noted)
	}
}

// A real agent may report no modes object; its mode then comes from the
// sealed config. Reasoning effort options are not permission modes.
func TestSessionResultWithoutModesUsesSealedConfig(t *testing.T) {
	real := func() map[string]any {
		return map[string]any{
			"sessionId": "s",
			"configOptions": []any{
				map[string]any{"id": "model", "category": "model", "currentValue": "m"},
				map[string]any{"id": "reasoning_effort", "category": "thought_level", "currentValue": "high"},
			},
			"_meta": map[string]any{"x.ai/sessionConfig": map[string]any{"options": []any{
				map[string]any{"id": "xhigh", "category": "mode", "selected": false},
			}}},
		}
	}
	if p := acpResultModeProblem(real()); p != "" {
		t.Fatal(p)
	}
	bad := real()
	bad["yolo"] = true
	if acpResultModeProblem(bad) == "" {
		t.Fatal("bypass flag accepted")
	}
	opt := real()
	opt["configOptions"] = append(opt["configOptions"].([]any), map[string]any{"id": "permission_mode", "currentValue": "always-approve"})
	if acpResultModeProblem(opt) == "" {
		t.Fatal("non-default permission option accepted")
	}
}
