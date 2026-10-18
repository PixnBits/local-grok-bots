package permission

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestMonitorClassifiesAsBash(t *testing.T) {
	ws := t.TempDir()
	mon := ClassifyCall("Monitor", map[string]any{"command": "pwd"}, ws)
	bash := ClassifyCall("Bash", map[string]any{"command": "pwd"}, ws)
	if mon.Kind != bash.Kind || mon.AutoAllow != bash.AutoAllow || !mon.AutoAllow {
		t.Fatalf("monitor %+v bash %+v", mon, bash)
	}
	loose := ClassifyCall("Monitor", map[string]any{"command": "cat a.txt"}, ws)
	if loose.AutoAllow {
		t.Fatal("file arguments were auto-allowed")
	}
}

func TestBrokerDeniesGenerationTools(t *testing.T) {
	var rows []map[string]any
	b := New(Options{Audit: func(rec map[string]any) {
		rows = append(rows, rec)
	}})
	pol := policy.Permission{Mode: "bypasspermissions", UIPrompts: false}
	ws := t.TempDir()
	cases := []struct {
		in, tool, rule string
	}{
		{"Task", "Task", "task"},
		{"workflow", "Workflow", "workflow"},
		{"scheduler_create", "Scheduler", "scheduler"},
		{"ImageGen", "ImageGen", "image"},
		{"image_to_video", "ImageToVideo", "image"},
		{"reference_to_video", "ReferenceToVideo", "image"},
	}
	for _, c := range cases {
		out := b.Evaluate(context.Background(), pol, Request{
			Tool: c.in, Workspace: ws, Args: map[string]any{"command": "pwd"},
		})
		if out.Decision != Deny || out.Source != "policy" || out.Rule != c.rule {
			t.Fatalf("%s %+v", c.in, out)
		}
	}
	if len(rows) != len(cases) {
		t.Fatalf("rows %d", len(rows))
	}
	for i, c := range cases {
		if rows[i]["event"] != "permission_decision" || rows[i]["tool"] != c.tool || rows[i]["rule"] != c.rule || rows[i]["decision"] != Deny {
			t.Fatalf("row %v", rows[i])
		}
	}
	out := b.Evaluate(context.Background(), pol, Request{Tool: "unknown", Workspace: ws})
	if out.Rule == "task" || out.Rule == "image" || out.Rule == "workflow" || out.Rule == "scheduler" {
		t.Fatalf("unknown %+v", out)
	}
}

func TestGrokHomeWriteDenied(t *testing.T) {
	b := New(Options{})
	ws := t.TempDir()
	home := t.TempDir()
	file := filepath.Join(ws, "a.txt")
	if err := os.WriteFile(file, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := policy.Permission{Mode: "bypasspermissions", UIPrompts: false}
	deny := func(tool string, args map[string]any) {
		t.Helper()
		out := b.Evaluate(context.Background(), pol, Request{
			Tool: tool, Workspace: ws, GrokHome: home, Args: args,
		})
		if out.Decision != Deny || out.Rule != "grok_home" || out.Source != "policy" {
			t.Fatalf("%s %+v", tool, out)
		}
	}
	deny("Edit", map[string]any{"file_path": filepath.Join(home, "config.toml")})
	deny("Write", map[string]any{"target_file": filepath.Join(home, "auth.json")})
	deny("Bash", map[string]any{"command": "touch " + filepath.Join(home, "x")})
	deny("Monitor", map[string]any{"command": "cat " + filepath.Join(home, "auth.json")})
	deny("Bash", map[string]any{"command": "echo $GROK_HOME/config.toml"})
	deny("Bash", map[string]any{"command": "echo hi >" + filepath.Join(home, "x")})
	out := b.Evaluate(context.Background(), pol, Request{
		Tool: "Edit", Workspace: ws, GrokHome: home,
		Args: map[string]any{"file_path": file},
	})
	if out.Decision != Allow || out.Source != "policy" {
		t.Fatalf("workspace edit %+v", out)
	}
	out = b.Evaluate(context.Background(), pol, Request{
		Tool: "Edit", Workspace: ws,
		Args: map[string]any{"file_path": file},
	})
	if out.Decision != Allow {
		t.Fatalf("empty home %+v", out)
	}
}
