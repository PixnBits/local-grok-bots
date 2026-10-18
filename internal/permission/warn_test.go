package permission

import (
	"strings"
	"testing"
)

func TestUnprefixedAllowWarning(t *testing.T) {
	warning, form := UnprefixedAllowWarning("Bash(cat *)")
	if form != "cat -- file" || !strings.Contains(warning, "cat -- file") {
		t.Fatalf("cat %q %q", warning, form)
	}
	warning, form = UnprefixedAllowWarning("Bash(cat  *)")
	if form != "cat -- file" {
		t.Fatalf("spaced %q %q", warning, form)
	}
	if warning, form = RuleWarning("deny", "Bash(cat *)"); warning != "" || form != "" {
		t.Fatalf("deny %q %q", warning, form)
	}
	if warning, form = RuleWarning("ask", "Bash(cat *)"); warning != "" || form != "" {
		t.Fatalf("ask %q %q", warning, form)
	}
	if warning, _ = UnprefixedAllowWarning("Bash(pwd)"); warning != "" {
		t.Fatalf("pwd %q", warning)
	}
	if warning, form = UnprefixedAllowWarning("Bash(grep *)"); form != "grep pattern -- file" || warning == "" {
		t.Fatalf("grep %q %q", warning, form)
	}
	if !ruleMatchesCall("Bash(cat  *)", Request{Tool: "Bash", Args: map[string]any{"command": "cat -- a.txt"}}, "cat -- a.txt") {
		t.Fatal("spaced rule did not match the dashed command")
	}
	if !ruleMatchesCall("Bash(cat *)", Request{Tool: "Bash", Args: map[string]any{"command": "cat a.txt"}}, "cat a.txt") {
		t.Fatal("glob no longer matches the unprefixed command")
	}
}
