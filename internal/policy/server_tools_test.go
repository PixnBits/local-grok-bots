package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerToolsPrecedence(t *testing.T) {
	plain := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n")
	p, err := Load(Options{Path: plain})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ServerTools) != 0 || p.ServerToolsSource != "default" {
		t.Fatalf("default %#v %s", p.ServerTools, p.ServerToolsSource)
	}

	localOnly := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"Web_Search\", \"web_search\", \"x_search\"]\n")
	p, err = Load(Options{Path: localOnly})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.ServerTools, ",") != "web_search,x_search" || p.ServerToolsSource != "local" {
		t.Fatalf("local %#v %s", p.ServerTools, p.ServerToolsSource)
	}

	local := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"web_search\", \"x_search\"]\n")
	managedDeny := writePolicyFile(t, "managed.json", `{"cli":{"server_tools":[]}}`)
	p, err = Load(Options{Path: local, ManagedPath: managedDeny})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ServerTools) != 0 || p.ServerToolsSource != "managed" {
		t.Fatalf("managed deny %#v %s", p.ServerTools, p.ServerToolsSource)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "x_search") || !strings.Contains(strings.Join(p.Warnings, "\n"), "only narrow") {
		t.Fatalf("warnings %#v", p.Warnings)
	}

	managedBoth := writePolicyFile(t, "managed.json", `{"cli":{"server_tools":["web_search","x_search"]}}`)
	localNarrow := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"web_search\"]\n")
	p, err = Load(Options{Path: localNarrow, ManagedPath: managedBoth})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.ServerTools, ",") != "web_search" || p.ServerToolsSource != "local" {
		t.Fatalf("narrow %#v %s", p.ServerTools, p.ServerToolsSource)
	}

	managedOne := writePolicyFile(t, "managed.json", `{"cli":{"server_tools":["web_search"]}}`)
	localWide := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"web_search\", \"x_search\"]\n")
	p, err = Load(Options{Path: localWide, ManagedPath: managedOne})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.ServerTools, ",") != "web_search" || p.ServerToolsSource != "managed" {
		t.Fatalf("widen %#v %s", p.ServerTools, p.ServerToolsSource)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "x_search") {
		t.Fatalf("warnings %#v", p.Warnings)
	}

	localEmpty := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = []\n")
	p, err = Load(Options{Path: localEmpty, ManagedPath: managedOne})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ServerTools) != 0 || p.ServerToolsSource != "local" {
		t.Fatalf("empty local %#v %s", p.ServerTools, p.ServerToolsSource)
	}

	allow, src := p.EffectiveServerTools(nil, false)
	if len(allow) != 0 || src != "local" {
		t.Fatalf("inherit %#v %s", allow, src)
	}
	bot := []string{"web_search"}
	allow, src = p.EffectiveServerTools(bot, true)
	if len(allow) != 0 || src != "local" {
		t.Fatalf("bot cannot widen %#v %s", allow, src)
	}

	p, err = Load(Options{Path: localNarrow, ManagedPath: managedBoth})
	if err != nil {
		t.Fatal(err)
	}
	allow, src = p.EffectiveServerTools([]string{"web_search", "x_search"}, true)
	if strings.Join(allow, ",") != "web_search" || src != "local" {
		t.Fatalf("bot superset %#v %s", allow, src)
	}
	allow, src = p.EffectiveServerTools([]string{}, true)
	if len(allow) != 0 || src != "bot" {
		t.Fatalf("bot empty %#v %s", allow, src)
	}
	allow, src = p.EffectiveServerTools(nil, false)
	if strings.Join(allow, ",") != "web_search" || src != "local" {
		t.Fatalf("bot unset %#v %s", allow, src)
	}

	bad := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"bad name\"]\n")
	p, err = Load(Options{Path: bad})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Warnings, "\n")
	if p.CLIPermitted || len(p.ServerTools) != 0 || strings.Contains(joined, "bad name") {
		t.Fatalf("invalid kept permitted %v tools %#v warnings %s", p.CLIPermitted, p.ServerTools, joined)
	}
	fn := writePolicyFile(t, "policy.toml", "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = [\"function\"]\n")
	p, err = Load(Options{Path: fn})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted || !strings.Contains(strings.Join(p.Warnings, "\n"), "function") {
		t.Fatalf("function list permitted %v warnings %#v", p.CLIPermitted, p.Warnings)
	}
	over := "[backend]\nbackend = \"ollama\"\n[cli]\nserver_tools = ["
	for i := 0; i < 33; i++ {
		if i > 0 {
			over += ", "
		}
		over += "\"t" + strconvI(i) + "\""
	}
	over += "]\n"
	p, err = Load(Options{Path: writePolicyFile(t, "policy.toml", over)})
	if err != nil {
		t.Fatal(err)
	}
	if p.CLIPermitted {
		t.Fatal("over-long list was accepted")
	}
}

func strconvI(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
