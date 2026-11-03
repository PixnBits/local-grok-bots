package daemon

import (
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/store"
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

func TestDescriptionWarningsNearEnd(t *testing.T) {
	const dottedI = "\u0130"
	const kelvin = "\u212A"
	cases := []struct {
		name string
		desc string
		want string
	}{
		{name: "snake in sentence", desc: "Summarise my_notes daily."},
		{name: "camel in sentence", desc: "Watch the dailyReport folder."},
		{name: "snake at end", desc: "my_notes"},
		{name: "camel at end", desc: "dailyReport"},
		{name: "use at end", desc: "use my_notes", want: "my_notes"},
		{name: "tool at start", desc: "my_notes tool", want: "my_notes"},
		{name: "fetch bucket cli", desc: "Use the Google Cloud CLI to list buckets with `fetch_bucket_list`."},
		{name: "multibyte sentence", desc: "Résumé über İstanbul, use KelvinK_tool ok"},
		{name: "dotted i before snake", desc: dottedI + "my_notes"},
		{name: "kelvin before snake", desc: kelvin + "my_notes"},
		{name: "dotted i after snake", desc: "my_notes" + dottedI},
		{name: "kelvin after snake", desc: "my_notes" + kelvin},
		{name: "dotted i and kelvin around snake", desc: dottedI + "my_notes" + kelvin},
		{name: "kelvin and dotted i around snake", desc: kelvin + "my_notes" + dottedI},
		{name: "use dotted i at end", desc: "use " + dottedI + "my_notes", want: "my_notes"},
		{name: "use kelvin at end", desc: "use " + kelvin + "my_notes", want: "my_notes"},
		{name: "dotted i then tool", desc: dottedI + "my_notes tool", want: "my_notes"},
		{name: "kelvin then tool", desc: "my_notes" + kelvin + " tool", want: "my_notes"},
		{name: "empty", desc: ""},
		{name: "whitespace", desc: " \t\n "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, rec := func() (out []string, rec any) {
				defer func() { rec = recover() }()
				return descriptionWarnings(c.desc), nil
			}()
			if rec != nil {
				t.Fatalf("%s: panic: %v", c.name, rec)
			}
			joined := strings.Join(w, "\n")
			if c.want == "" {
				if strings.Contains(joined, "tool-like name") {
					t.Fatalf("%s: unexpected tool-like warning %q", c.name, w)
				}
				return
			}
			want := `tool-like name "` + c.want + `"`
			if !strings.Contains(joined, want) {
				t.Fatalf("%s: warnings %q lack %s", c.name, w, want)
			}
		})
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
	var bot struct {
		ID       string
		Warnings []store.Warning `json:"warnings"`
	}
	decodeJSON(t, b, &bot)
	if len(bot.Warnings) != 1 || bot.Warnings[0].Field != "description" || strings.Contains(bot.Warnings[0].Text, "Saving still works") {
		t.Fatalf("create warnings = %+v", bot.Warnings)
	}
	_, b = do(t, "GET", srv.URL+"/api/bots/"+bot.ID, nil, "")
	var got struct {
		Warnings []store.Warning `json:"warnings"`
	}
	decodeJSON(t, b, &got)
	if len(got.Warnings) != 1 || got.Warnings[0].Field != "description" || got.Warnings[0].Text != bot.Warnings[0].Text {
		t.Fatalf("warnings = %+v", got.Warnings)
	}
}

func TestListBotsIncludesWarnings(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": "Smith", "description": codeSmithDesc}, "")
	if res.StatusCode != 200 && res.StatusCode != 201 {
		t.Fatalf("create %d %s", res.StatusCode, b)
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeJSON(t, b, &created)
	res, b = do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("list %d %s", res.StatusCode, b)
	}
	var bots []struct {
		ID       string          `json:"id"`
		Warnings []store.Warning `json:"warnings"`
	}
	decodeJSON(t, b, &bots)
	var found bool
	for _, bot := range bots {
		if bot.ID != created.ID {
			continue
		}
		found = true
		if len(bot.Warnings) != 1 || bot.Warnings[0].Field != "description" {
			t.Fatalf("list warnings = %+v", bot.Warnings)
		}
	}
	if !found {
		t.Fatalf("bot %s missing from list %s", created.ID, b)
	}
}

func TestListBotsNearEndDescriptions(t *testing.T) {
	app := newApp(t, "", fakeModel{})
	srv := serve(t, app)
	created := map[string]string{}
	for _, c := range []struct {
		name string
		desc string
	}{
		{"Notes", "Summarise my_notes daily."},
		{"Report", "Watch the dailyReport folder."},
		{"Clean", "You summarize the news each morning."},
	} {
		res, b := do(t, "POST", srv.URL+"/api/bots", map[string]string{"name": c.name, "description": c.desc}, "")
		if res.StatusCode != 200 && res.StatusCode != 201 {
			t.Fatalf("create %s %d %s", c.name, res.StatusCode, b)
		}
		var bot struct {
			ID string `json:"id"`
		}
		decodeJSON(t, b, &bot)
		if bot.ID == "" {
			t.Fatalf("create %s missing id %s", c.name, b)
		}
		created[bot.ID] = c.name
	}
	res, b := do(t, "GET", srv.URL+"/api/bots", nil, "")
	if res.StatusCode != 200 {
		t.Fatalf("list %d %s", res.StatusCode, b)
	}
	var bots []struct {
		ID string `json:"id"`
	}
	decodeJSON(t, b, &bots)
	found := map[string]bool{}
	for _, bot := range bots {
		found[bot.ID] = true
	}
	for id, name := range created {
		if !found[id] {
			t.Fatalf("bot %s (%s) missing from list %s", id, name, b)
		}
	}
	patches := []string{"use my_notes", "dailyReport", "Summarise my_notes daily."}
	i := 0
	for id := range created {
		res, b = do(t, "GET", srv.URL+"/api/bots/"+id, nil, "")
		if res.StatusCode != 200 {
			t.Fatalf("get %s %d %s", id, res.StatusCode, b)
		}
		var got struct {
			ID string `json:"id"`
		}
		decodeJSON(t, b, &got)
		if got.ID != id {
			t.Fatalf("get id %s body %s", id, b)
		}
		res, b = do(t, "GET", srv.URL+"/api/bots/"+id+"/state", nil, "")
		if res.StatusCode != 200 {
			t.Fatalf("state %s %d %s", id, res.StatusCode, b)
		}
		var st botState
		decodeJSON(t, b, &st)
		res, b = do(t, "PATCH", srv.URL+"/api/bots/"+id, map[string]string{"description": patches[i%len(patches)]}, "")
		if res.StatusCode != 200 {
			t.Fatalf("patch %s %d %s", id, res.StatusCode, b)
		}
		var patched struct {
			ID string `json:"id"`
		}
		decodeJSON(t, b, &patched)
		if patched.ID != id {
			t.Fatalf("patch id %s body %s", id, b)
		}
		i++
	}
}
