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
		"upserted":      []any{map[string]any{"yolo": false, "mode": "default"}},
	}) != "" {
		t.Fatal("changed default")
	}
	if acpUpdateModeProblem(map[string]any{
		"sessionUpdate": "_x.ai/sessions/changed",
		"info":          map[string]any{"mode": "default"},
	}) == "" {
		t.Fatal("changed without yolo")
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
	for _, s := range []string{
		"\uFEFF/status",
		"\u200B/status",
		"\u200C /status",
		"\u00A0/status",
		"\u3000/status",
		"\uFF0Fstatus",
		"\u2215status",
		"\u2044status",
		"\uFEFF\u200B \uFF0Fstatus",
	} {
		if !SlashPrompt(s) {
			t.Fatalf("missed %q", s)
		}
	}
	if SlashPrompt("please \uFF0Fstatus") || SlashPrompt("\uFEFFplease") || !SlashPrompt("\u29F8") {
		t.Fatal("slash look-alike")
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
	noted = ""
	_, err = (ExecRunner{}).Run(context.Background(), Spec{
		Backend: "grok", Prompt: "\uFF0Fstatus", Workspace: t.TempDir(),
		ACP: &ACPHooks{Fail: func(tool string, args map[string]any, reason string) {
			noted = tool + " " + reason
		}},
	}, nil)
	if !errors.Is(err, ErrSlash) || !strings.Contains(noted, ErrSlash.Error()) {
		t.Fatalf("look-alike %v %s", err, noted)
	}
}

func TestSessionChangedUpsert(t *testing.T) {
	bad := map[string]any{
		"method": "_x.ai/sessions/changed",
		"params": map[string]any{"upserted": []any{map[string]any{"yolo": true}}},
	}
	if sessionsChangedProblem(bad) == "" || !sessionChangedMethod("_x.ai/sessions/changed") {
		t.Fatal("yolo true")
	}
	alias := map[string]any{
		"method": "x.ai/sessions/changed",
		"params": map[string]any{"upserted": []any{map[string]any{"mode": "other", "yolo": false}}},
	}
	if sessionsChangedProblem(alias) == "" || !sessionChangedMethod("x.ai/sessions/changed") {
		t.Fatal("alias mode")
	}
	ok := map[string]any{
		"params": map[string]any{"upserted": []any{map[string]any{"yolo": false, "mode": "default"}}},
	}
	if sessionsChangedProblem(ok) != "" {
		t.Fatal(sessionsChangedProblem(ok))
	}
	nested := map[string]any{"params": map[string]any{"upserted": []any{[]any{map[string]any{"yolo": true}}}}}
	if sessionsChangedProblem(nested) == "" {
		t.Fatal("nested list")
	}
	nestedOK := map[string]any{"params": map[string]any{"upserted": []any{[]any{map[string]any{"yolo": false}}}}}
	if sessionsChangedProblem(nestedOK) != "" {
		t.Fatal(sessionsChangedProblem(nestedOK))
	}
	if sessionsChangedProblem(map[string]any{"method": "_x.ai/sessions/changed"}) == "" {
		t.Fatal("missing params")
	}
	missing := map[string]any{"params": map[string]any{"upserted": []any{map[string]any{"mode": "default"}}}}
	if sessionsChangedProblem(missing) == "" {
		t.Fatal("missing yolo")
	}
	text := map[string]any{"params": map[string]any{"upserted": []any{map[string]any{"yolo": "false"}}}}
	if sessionsChangedProblem(text) == "" {
		t.Fatal("string yolo")
	}
	num := map[string]any{"params": map[string]any{"upserted": []any{map[string]any{"yolo": float64(0)}}}}
	if sessionsChangedProblem(num) == "" {
		t.Fatal("number yolo")
	}
	empty := map[string]any{"params": map[string]any{"upserted": []any{}, "removed": []any{map[string]any{"sessionId": "s"}}}}
	if sessionsChangedProblem(empty) != "" {
		t.Fatal(sessionsChangedProblem(empty))
	}
	if sessionChangedMethod("session/update") {
		t.Fatal("ordinary update")
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
