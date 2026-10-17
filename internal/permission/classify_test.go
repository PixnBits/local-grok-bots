package permission

import "testing"

func TestClassifyCall(t *testing.T) {
	ws := t.TempDir()
	cases := []struct {
		name string
		tool string
		args map[string]any
		want bool
		kind string
		risk string
		sens string
	}{
		{"gh view", "Bash", map[string]any{"command": "gh pr view 42"}, true, "read_only", "low", "project"},
		{"gh diff repo", "Bash", map[string]any{"command": "gh pr diff --repo owner/name 7"}, true, "read_only", "low", "project"},
		{"git status", "Bash", map[string]any{"command": "git status -sb"}, true, "read_only", "low", "project"},
		{"git log", "Bash", map[string]any{"command": "git log -5 --oneline"}, true, "read_only", "low", "project"},
		{"push", "Bash", map[string]any{"command": "git push origin main"}, false, "irreversible", "high", "unknown"},
		{"rm", "Bash", map[string]any{"command": "rm -rf /tmp/x"}, false, "irreversible", "high", "unknown"},
		{"curl", "Bash", map[string]any{"command": "curl https://example.com"}, false, "network", "high", "unknown"},
		{"redirect", "Bash", map[string]any{"command": "git status > /tmp/out"}, false, "mixed", "high", "unknown"},
		{"composed", "Bash", map[string]any{"command": "gh pr view 42; rm -rf /tmp/x"}, false, "mixed", "high", "unknown"},
		{"and", "Bash", map[string]any{"command": "gh pr view 42 && git push"}, false, "mixed", "high", "unknown"},
		{"subst", "Bash", map[string]any{"command": "gh pr view $(id)"}, false, "mixed", "high", "unknown"},
		{"cat inside", "Bash", map[string]any{"command": "cat src/main.go"}, true, "read_only", "low", "project"},
		{"cat etc", "Bash", map[string]any{"command": "cat /etc/passwd"}, false, "system", "high", "system"},
		{"ssh key", "Bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}, false, "credential", "high", "credential"},
		{"find delete", "Bash", map[string]any{"command": "find . -delete"}, false, "write", "high", "unknown"},
		{"read src", "Read", map[string]any{"file_path": "src/main.go"}, true, "read_only", "low", "project"},
		{"read env", "Read", map[string]any{"file_path": ".env"}, false, "credential", "high", "credential"},
		{"edit", "Edit", map[string]any{"file_path": "src/main.go"}, false, "write", "high", "project"},
		{"web", "WebFetch", map[string]any{"url": "https://example.com"}, false, "network", "high", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyCall(tc.tool, tc.args, ws)
			if got.AutoAllow != tc.want || got.Kind != tc.kind || got.Risk != tc.risk || got.Sensitivity != tc.sens {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestCheckUserRule(t *testing.T) {
	ws := t.TempDir()
	ok, err := CheckUserRule("allow", "Bash(gh pr view *)", ws)
	if err != nil || !ok.AutoAllow || ok.Risk != "low" || ok.Kind != "read_only" {
		t.Fatalf("gh pattern %+v %v", ok, err)
	}
	if _, err := CheckUserRule("allow", "Bash(git status*)", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUserRule("allow", "Read(./src/**)", ws); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"Bash(git push *)",
		"Bash(rm -rf *)",
		"Bash(curl *)",
		"Bash(*push*)",
		"Bash(*)",
		"Read",
		"Read(**/.env)",
		"Edit(./src/**)",
		"Bash",
	} {
		if _, err := CheckUserRule("allow", p, ws); err == nil {
			t.Fatalf("allowed %s", p)
		}
	}
	if _, err := CheckUserRule("deny", "Bash(*push*)", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUserRule("ask", "Bash(git push *)", ws); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUserRule("bypass", "Bash(git status)", ws); err == nil {
		t.Fatal("bypass effect accepted")
	}
}
