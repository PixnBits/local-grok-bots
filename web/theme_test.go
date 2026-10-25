package web

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Theme and mark-colour behaviour of the single embedded page.
// Static checks lock the token set; node runs the head theme script and paintMark.

func TestThemeStatic(t *testing.T) {
	src := string(IndexHTML)
	if !strings.Contains(src, `<meta name="color-scheme" content="light dark">`) {
		t.Error("missing meta color-scheme")
	}
	for _, sel := range []string{
		":root {",
		"@media (prefers-color-scheme: dark)",
		":root:not([data-theme=light])",
		":root[data-theme=dark]",
	} {
		if !strings.Contains(src, sel) {
			t.Errorf("missing theme selector %s", sel)
		}
	}
	if !strings.Contains(src, ":focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }") {
		t.Error("missing global focus ring")
	}
	for _, bad := range []string{"outline: none", "outline:none", "outline: 0", "outline:0"} {
		if strings.Contains(src, bad) {
			t.Errorf("index.html contains %q", bad)
		}
	}
	if strings.Contains(strings.ToLower(src), "#e4ddd0") {
		t.Error("index.html still has #e4ddd0")
	}
	if stripped := strings.ReplaceAll(strings.ToLower(src), "sans-serif", ""); strings.Contains(stripped, "serif") {
		t.Error("index.html contains a serif font")
	}
	urls := strings.ReplaceAll(src, "http://www.w3.org/2000/svg", "")
	for _, scheme := range []string{"http://", "https://"} {
		if i := strings.Index(urls, scheme); i >= 0 {
			lo := i - 40
			if lo < 0 {
				lo = 0
			}
			hi := i + 60
			if hi > len(urls) {
				hi = len(urls)
			}
			t.Errorf("unexpected %s near %q", scheme, urls[lo:hi])
		}
	}

	light := cssBlock(t, src, ":root {")
	media := cssBlock(t, src, "@media (prefers-color-scheme: dark)")
	dark := cssBlock(t, src, ":root[data-theme=dark]")
	if strings.Contains(light, "#0F0F11") {
		t.Error("light block contains the dark background")
	}
	for _, block := range []string{media, dark} {
		if strings.Contains(block, "#F6F6F7") {
			t.Error("dark block contains the light background")
		}
	}
	if !strings.Contains(light, "color-scheme: light") {
		t.Error("light block missing color-scheme: light")
	}
	for _, block := range []string{media, dark} {
		if !strings.Contains(block, "color-scheme: dark") {
			t.Error("dark block missing color-scheme: dark")
		}
	}
	for _, name := range colorTokenNames {
		for _, block := range []struct{ label, body string }{
			{"light", light},
			{"prefers-color-scheme", media},
			{"data-theme=dark", dark},
		} {
			if !tokenSet(block.body, name) {
				t.Errorf("%s block missing --%s", block.label, name)
			}
		}
	}
	if !strings.Contains(src, "--mark-fallback: #787B8A;") {
		t.Error("missing --mark-fallback: #787B8A")
	}
	if !strings.Contains(media, "--code-inline: rgba(255,255,255,.10);") || !strings.Contains(dark, "--code-inline: rgba(255,255,255,.10);") {
		t.Error("dark code-inline must be rgba(255,255,255,.10)")
	}
	if strings.Contains(src, "rgba(255,255,255,.09)") {
		t.Error("dark code-inline uses the mockup alpha")
	}
	for _, s := range []string{
		`--font: system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Helvetica Neue", Arial, sans-serif;`,
		`--mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "DejaVu Sans Mono", monospace;`,
		"--fs-xs: 12px", "--lh-xs: 16px",
		"--fs-sm: 13px", "--lh-sm: 18px",
		"--fs-body: 15px", "--lh-body: 22px",
		"--fs-title: 17px", "--lh-title: 24px",
		"--fs-h: 20px", "--lh-h: 28px",
		"--fs-d: 24px", "--lh-d: 32px",
		"--r-chip: 6px", "--r-control: 10px", "--r-card: 14px", "--r-bubble: 18px", "--r-sheet: 20px",
		"--space-4: 4px", "--space-8: 8px", "--space-12: 12px", "--space-16: 16px", "--space-20: 20px",
		"--space-24: 24px", "--space-32: 32px", "--space-40: 40px", "--space-48: 48px",
		"--e1: 0 1px 2px rgba(16,16,20,.06);",
		"--e2: 0 2px 6px rgba(16,16,20,.06), 0 8px 24px rgba(16,16,20,.08);",
		"--e3: 0 4px 12px rgba(16,16,20,.08), 0 24px 48px rgba(16,16,20,.16);",
		"--e1: 0 1px 2px rgba(0,0,0,.18);",
		"--e2: 0 2px 6px rgba(0,0,0,.18), 0 8px 24px rgba(0,0,0,.24);",
		"--e3: 0 4px 12px rgba(0,0,0,.24), 0 24px 48px rgba(0,0,0,.48);",
		`.mark::before { background: var(--mark-edge); }`,
		`.mark::after { inset: 2px; background: var(--c, var(--mark-fallback)); }`,
		`<option value="system">System</option>`,
		`<option value="light">Light</option>`,
		`<option value="dark">Dark</option>`,
		`localStorage.setItem("lgb.theme", mode)`,
		`localStorage.getItem("lgb.theme")`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	presets := []string{"#4C77DD", "#218C57", "#A8700E", "#D44E4A", "#8B60ED", "#10898E", "#C65C2F", "#787B8A"}
	i := strings.Index(src, "const COLORS = [")
	if i < 0 {
		t.Fatal("COLORS list missing")
	}
	j := strings.Index(src[i:], "]")
	if j < 0 {
		t.Fatal("COLORS list not closed")
	}
	arr := src[i : i+j]
	pos := 0
	for _, hex := range presets {
		p := strings.Index(arr[pos:], hex)
		if p < 0 {
			t.Errorf("preset %s missing or out of order in %s", hex, arr)
			continue
		}
		pos += p + len(hex)
	}
	names := []string{"Blue", "Green", "Gold", "Red", "Violet", "Teal", "Rust", "Slate"}
	k := strings.Index(src, "const COLOR_NAMES = ")
	if k < 0 {
		t.Fatal("COLOR_NAMES missing")
	}
	line := src[k:]
	if end := strings.Index(line, "\n"); end >= 0 {
		line = line[:end]
	}
	pos = 0
	for _, name := range names {
		p := strings.Index(line[pos:], name)
		if p < 0 {
			t.Errorf("colour name %s missing or out of order", name)
			continue
		}
		pos += p + len(name)
	}
}

var colorTokenNames = []string{
	"bg", "surface", "surface-2", "surface-3", "sel",
	"border", "border-strong", "border-control",
	"text", "text-2", "muted",
	"accent", "accent-hover", "accent-text", "accent-soft", "on-accent",
	"user-bubble", "user-bubble-text", "bot-bubble",
	"attention", "attention-text", "attention-soft", "on-attention",
	"danger", "danger-text", "danger-soft", "on-danger",
	"success", "success-text", "success-soft",
	"status-idle", "status-running", "status-paused",
	"code-bg", "code-text", "code-muted",
	"focus", "stop-fill", "on-stop", "mark-fallback",
	"mark-edge", "code-inline", "scrim",
}

func tokenSet(block, name string) bool {
	re := regexp.MustCompile(`(?m)(?:^|[^-])--` + regexp.QuoteMeta(name) + `\s*:`)
	return re.MatchString(block)
}

func cssBlock(t *testing.T, src, start string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("missing %s", start)
	}
	rest := src[i:]
	j := strings.Index(rest, "{")
	if j < 0 {
		t.Fatalf("missing brace after %s", start)
	}
	depth := 0
	for k := j; k < len(rest); k++ {
		switch rest[k] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[j+1 : k]
			}
		}
	}
	t.Fatalf("unbalanced brace after %s", start)
	return ""
}

func between(t *testing.T, src, begin, end string) string {
	t.Helper()
	i := strings.Index(src, begin)
	j := strings.Index(src, end)
	if i < 0 || j < i {
		t.Fatalf("markers %s / %s missing", begin, end)
	}
	return src[i+len(begin) : j]
}

func TestThemeApply(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// theme:begin", "// theme:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
function run(kind, initial) {
  const el = {
    attr: initial || "",
    setAttribute(name, value) { if (name === "data-theme") this.attr = value; },
    removeAttribute(name) { if (name === "data-theme") this.attr = ""; }
  };
  let storage;
  if (kind === "throw") {
    storage = new Proxy({}, { get() { throw new Error("blocked"); } });
  } else {
    storage = { getItem() { return kind === "missing" ? null : kind; } };
  }
  const sandbox = { localStorage: storage, document: { documentElement: el } };
  vm.createContext(sandbox);
  vm.runInContext(snippet, sandbox);
  return el.attr;
}
const cases = [
  ["missing", "", ""],
  ["bogus", "", ""],
  ["throw", "", ""],
  ["system", "dark", ""],
  ["light", "", "light"],
  ["dark", "", "dark"]
];
const got = cases.map(([kind, initial]) => run(kind, initial));
console.log(JSON.stringify(got));
`
	got := runNode(t, node, script)
	var attrs []string
	if err := json.Unmarshal([]byte(got), &attrs); err != nil {
		t.Fatalf("decode %v: %s", err, got)
	}
	want := []string{"", "", "", "", "light", "dark"}
	if len(attrs) != len(want) {
		t.Fatalf("got %v", attrs)
	}
	for i, w := range want {
		if attrs[i] != w {
			t.Errorf("case %d: got %q want %q", i, attrs[i], w)
		}
	}
}

func TestPaintMarkColor(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// mark:begin", "// mark:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\nthis.paintMark = paintMark;", ctx);
function apply(mark) {
  const props = {};
  const el = { dataset: {}, style: { setProperty(k, v) { props[k] = v; }, removeProperty(k) { delete props[k]; } } };
  try { ctx.paintMark(el, mark); } catch (e) { return "threw:" + e.message; }
  return props["--c"] || "";
}
const cases = [
  {color: "#abc"},
  {color: "#4C77DD"},
  {color: "#1d4e89"},
  {color: "nope"},
  {color: ""},
  {},
  null,
  undefined
];
const seq = { dataset: {}, props: {}, style: null };
seq.style = { setProperty(k, v) { seq.props[k] = v; }, removeProperty(k) { delete seq.props[k]; } };
ctx.paintMark(seq, {color: "#abc"});
const kept = seq.props["--c"] || "";
ctx.paintMark(seq, {color: "nope"});
const cleared = seq.props["--c"] || "";
console.log(JSON.stringify({got: cases.map(apply), kept, cleared, nullMark: apply(null)}));
`
	out := runNode(t, node, script)
	var result struct {
		Got      []string `json:"got"`
		Kept     string   `json:"kept"`
		Cleared  string   `json:"cleared"`
		NullMark string   `json:"nullMark"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	want := []string{"#abc", "#4C77DD", "#1d4e89", "", "", "", "", ""}
	if len(result.Got) != len(want) {
		t.Fatalf("got %v", result.Got)
	}
	for i, w := range want {
		if result.Got[i] != w {
			t.Errorf("case %d: got %q want %q", i, result.Got[i], w)
		}
	}
	if result.Kept != "#abc" {
		t.Errorf("valid colour did not set --c, got %q", result.Kept)
	}
	if result.Cleared != "" {
		t.Errorf("invalid colour left --c = %q", result.Cleared)
	}
	if result.NullMark != "" {
		t.Errorf("null mark: %q", result.NullMark)
	}
}

func runNode(t *testing.T, node, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.js")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}
