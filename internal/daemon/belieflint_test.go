package daemon

import (
	"strings"
	"testing"
)

const codeSmithDesc = "You are a coding bot. You always use the Grok Build CLI to make changes to code. When asked to write, modify, or debug code, you must use the Grok Build CLI via shell commands to perform all file edits and operations. Do not use the built-in file tools (write_file, read_file) for code changes — always route through the Grok Build CLI instead."

func TestDescriptionWarnings(t *testing.T) {
	w := descriptionWarnings(codeSmithDesc)
	if len(w) != 1 || !strings.Contains(w[0], `"Grok Build CLI"`) || !strings.Contains(w[0], "grok-build") {
		t.Fatalf("warnings = %q", w)
	}
	w = descriptionWarnings("Run `zzqx-nope --fast` then call the fetch_url tool. Use `sh` and `go test ./...`. Edit `main.go` with write_file.")
	joined := strings.Join(w, "\n")
	for _, want := range []string{"`zzqx-nope`", `"fetch_url"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings %q lack %s", w, want)
		}
	}
	for _, bad := range []string{"`sh`", "`go`", "main.go", "write_file"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("warnings %q flag %s", w, bad)
		}
	}
	if w := descriptionWarnings("You summarize the news each morning."); len(w) != 0 {
		t.Fatalf("plain description warned: %q", w)
	}
}

func TestMemoryRejectsToolClaims(t *testing.T) {
	for _, c := range [][2]string{
		{"tools", "I only have write_memory and delete_memory"},
		{"limits", "I don't have run_shell"},
		{"env", "no access to tools besides memory"},
	} {
		if !memoryClaimsTools(c[0], c[1]) {
			t.Errorf("not caught: %q", c)
		}
	}
	for _, c := range [][2]string{
		{"favorite_color", "blue"},
		{"project", "uses run_shell to build with go"},
		{"user", "cannot make Tuesday meetings"},
	} {
		if memoryClaimsTools(c[0], c[1]) {
			t.Errorf("false positive: %q", c)
		}
	}
}

func TestWriteMemoryToolClaimErrors(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	bot, err := app.st.CreateBot("Ada", "help", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.execTool(t.Context(), bot, "write_memory", map[string]any{"key": "tools", "value": "I only have write_memory and delete_memory"})
	if err == nil || !strings.Contains(err.Error(), "attached fresh") {
		t.Fatalf("err = %v", err)
	}
	if mem, _ := app.st.ListMemory(bot.ID); len(mem) != 0 {
		t.Fatalf("stored %v", mem)
	}
}

func TestGetBotIncludesWarnings(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Smith", "description": codeSmithDesc}, "")
	if res.StatusCode != 200 && res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var bot struct{ ID string }
	decodeJSON(t, b, &bot)
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	var got struct {
		Warnings []string `json:"warnings"`
	}
	decodeJSON(t, b, &got)
	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %q", got.Warnings)
	}
}
