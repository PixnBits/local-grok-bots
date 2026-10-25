package web

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Layout shell, drill-down history, and the state-sheet container.
// Node runs the routing helpers and the sheet focus trap.

func TestLayoutStatic(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		"height: 100dvh;",
		"overflow: hidden;",
		"grid-template-columns: 280px minmax(0, 1fr);",
		"max-width: 800px;",
		"--thread-pad: 24px;",
		"--thread-pad: 12px;",
		"@media (min-width: 980px)",
		"@media (max-width: 979px)",
		"@media (max-width: 540px)",
		"grid-template-columns: 220px minmax(0, 720px);",
		"gap: 32px;",
		"height: 56px;",
		"max-width: 85%;",
		"border-left: 0;",
		"border-right: 0;",
		"flex: 1 1 100%;",
		"min-height: 44px;",
		"width: 400px;",
		"height: 75%;",
		"border-radius: 20px 20px 0 0;",
		".sheet-grab",
		`role="dialog"`,
		`aria-modal="true"`,
		`aria-label="Close"`,
		`aria-label="Appearance"`,
		`aria-label="Back"`,
		`id="thread-back"`,
		`id="solo-back"`,
		"@media (prefers-reduced-motion: reduce)",
		"transition: none;",
		"animation: none;",
		`e.key === "Escape"`,
		`e.key === "Tab"`,
		"function trapStateTab",
		"function onStateKey",
		"history.pushState",
		"history.back",
		`addEventListener("popstate"`,
		"#profile",
		"#log",
		"function navBack",
		"function parseLevel",
		".roster-head { height: 64px;",
		"<h1>Bots</h1>",
		`<footer class="roster-foot"><p id="health">`,
		`id="theme-select"`,
		`id="log-toggle"`,
		`" · state"`,
		`class="mark mark-20" id="state-sheet-mark"`,
		`.mark.mark-20 { width: 20px; height: 20px; }`,
		`class="solo-bar"`,
		`id="log-back"`,
		`class="solo-kicker">Profile</span>`,
		`<h2 class="solo-title">Log</h2>`,
		`id="profile-log"`,
		"gap: 0;",
		"border-right: 1px solid var(--border);",
		".roster-head, .thread-bar, .solo-bar { height: 56px; }",
		`<title>Local Grok Bots</title>`,
		`b.name + " — Local Grok Bots"`,
		"openState(btn)",
		"function restoreStateFocus",
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	for _, s := range []string{
		`role="tablist"`,
		`role="tab"`,
		`nav class="tabs"`,
		"nav.tabs",
		`data-view=`,
		`id="profile-back"`,
		"header.top",
		`class="top"`,
		"<h1>Local Grok Bots</h1>",
		">Back</button>",
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has %q", s)
		}
	}
	foot := strings.Index(src, `class="roster-foot"`)
	health := strings.Index(src, `id="health"`)
	if foot < 0 || health < foot {
		t.Fatal("#health must sit in the roster footer")
	}
	end := strings.Index(src[foot:], "</footer>")
	if end < 0 || health > foot+end {
		t.Fatal("#health must sit in the roster footer")
	}
	if strings.Contains(src, `+ "/profile"`) || strings.Contains(src, `+"/profile"`) {
		t.Error("profile must stay on the bot URL, not a /profile path")
	}
}

func TestNoRemoteAssetURLs(t *testing.T) {
	src := strings.ReplaceAll(string(IndexHTML), "http://www.w3.org/2000/svg", "")
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)@import\s+["']?https?:`),
		regexp.MustCompile(`(?i)url\(\s*["']?https?:`),
		regexp.MustCompile(`(?i)\ssrc\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)\shref\s*=\s*["']https?:`),
	}
	for _, re := range patterns {
		if loc := re.FindStringIndex(src); loc != nil {
			t.Errorf("remote asset reference %q", src[loc[0]:loc[1]])
		}
	}
}

func TestDrillDownRouting(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// route:begin", "// route:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\nthis.parseLevel=parseLevel; this.levelURL=levelURL; this.backAction=backAction; this.parentLevel=parentLevel; this.botFromPathname=botFromPathname;", ctx);
const out = [];
function eq(name, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  out.push({name, ok, got, want});
}
eq("home", ctx.parseLevel("/", "", "", null), {view:"bots", bot:null});
eq("hash-profile-without-bot", ctx.parseLevel("/", "#profile", "", null), {view:"bots", bot:null});
eq("thread", ctx.parseLevel("/bots/abc", "", "", null), {view:"chat", bot:"abc"});
eq("profile-hash", ctx.parseLevel("/bots/abc", "#profile", "", null), {view:"profile", bot:"abc"});
eq("log-hash", ctx.parseLevel("/bots/abc", "#log", "", null), {view:"log", bot:"abc"});
eq("log-home", ctx.parseLevel("/", "#log", "", null), {view:"log", bot:null});
eq("prefix", ctx.parseLevel("/hds-ab-1-cd/bots/a%2Fb", "#profile", "/hds-ab-1-cd", null), {view:"profile", bot:"a/b"});
eq("state-profile", ctx.parseLevel("/bots/abc", "", "", {lgb:1, view:"profile", bot:"abc", idx:2}), {view:"profile", bot:"abc"});
eq("hash-wins", ctx.parseLevel("/bots/abc", "#log", "", {lgb:1, view:"profile", bot:"abc", idx:2}), {view:"log", bot:"abc"});
eq("url-profile", ctx.levelURL("", "profile", "a b", "?t=1"), "/bots/a%20b?t=1#profile");
eq("url-thread", ctx.levelURL("", "chat", "abc", ""), "/bots/abc");
eq("url-home", ctx.levelURL("/hds-ab-1-cd", "bots", null, ""), "/hds-ab-1-cd/");
eq("url-log", ctx.levelURL("", "log", "abc", ""), "/bots/abc#log");
const profileURL = ctx.levelURL("", "profile", "abc", "");
eq("no-profile-path", profileURL.indexOf("/profile") === -1 && profileURL === "/bots/abc#profile", true);
eq("back-deep", ctx.backAction({lgb:1, idx:0, view:"chat", bot:"abc"}), "up");
eq("back-pushed", ctx.backAction({lgb:1, idx:2, view:"profile", bot:"abc"}), "back");
eq("back-foreign", ctx.backAction(null), "up");
eq("back-unstamped", ctx.backAction({idx:3}), "up");
eq("up-profile", ctx.parentLevel({view:"profile", bot:"abc"}), {view:"chat", bot:"abc"});
eq("up-thread", ctx.parentLevel({view:"chat", bot:"abc"}), {view:"bots", bot:null});
eq("up-log", ctx.parentLevel({view:"log", bot:"abc"}), {view:"chat", bot:"abc"});
eq("up-log-home", ctx.parentLevel({view:"log", bot:null}), {view:"bots", bot:null});
function backFrom(level, hist) {
  if (ctx.backAction(hist) === "back") return {op:"history.back"};
  const parent = ctx.parentLevel(level);
  return {op:"up", view:parent.view, bot:parent.bot, url:ctx.levelURL("", parent.view, parent.bot, "")};
}
eq("phone-profile-back", backFrom({view:"profile", bot:"abc"}, {lgb:1, idx:2, view:"profile", bot:"abc"}), {op:"history.back"});
eq("phone-thread-back", backFrom({view:"chat", bot:"abc"}, {lgb:1, idx:1, view:"chat", bot:"abc"}), {op:"history.back"});
eq("deep-thread-back", backFrom({view:"chat", bot:"abc"}, {lgb:1, idx:0, view:"chat", bot:"abc"}), {op:"up", view:"bots", bot:null, url:"/"});
eq("deep-profile-back", backFrom({view:"profile", bot:"abc"}, {lgb:1, idx:0, view:"profile", bot:"abc"}), {op:"up", view:"chat", bot:"abc", url:"/bots/abc"});
console.log(JSON.stringify(out));
`
	raw := runNode(t, node, script)
	var rows []struct {
		Name string          `json:"name"`
		OK   bool            `json:"ok"`
		Got  json.RawMessage `json:"got"`
		Want json.RawMessage `json:"want"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("decode %v: %s", err, raw)
	}
	if len(rows) == 0 {
		t.Fatal("no routing cases")
	}
	for _, row := range rows {
		if !row.OK {
			t.Errorf("%s: got %s want %s", row.Name, row.Got, row.Want)
		}
	}
}

func TestStateFocusTrap(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// focus:begin", "// focus:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\nthis.stateFocusables=stateFocusables; this.trapStateTab=trapStateTab;", ctx);
function el(opts) {
  opts = opts || {};
  return {
    disabled: !!opts.disabled,
    hidden: !!opts.hidden,
    getAttribute(name) { return name === "tabindex" ? (opts.tab == null ? null : opts.tab) : null; },
    focus() { this.focused = (this.focused || 0) + 1; },
    focused: 0
  };
}
const a = el();
const b = el();
const disabled = el({disabled:true});
const hidden = el({hidden:true});
const neg = el({tab:"-1"});
const root = {
  nodes: [disabled, a, neg, hidden, b],
  querySelectorAll() { return this.nodes; },
  contains(node) { return this.nodes.indexOf(node) >= 0; }
};
function ev(shift) {
  return { key:"Tab", shiftKey:!!shift, prevented:false, preventDefault() { this.prevented = true; } };
}
const focusable = ctx.stateFocusables(root).map(n => n === a ? "a" : n === b ? "b" : "?");
const cases = [];
function run(name, shift, active, wantPrevent, wantFocus) {
  a.focused = 0; b.focused = 0;
  const e = ev(shift);
  const trapped = ctx.trapStateTab(e, root, active);
  const focused = a.focused ? "a" : b.focused ? "b" : "";
  cases.push({
    name,
    ok: trapped === true && e.prevented === wantPrevent && focused === wantFocus,
    trapped, prevented: e.prevented, focused, wantPrevent, wantFocus
  });
}
const mid = ev(false);
const midTrapped = ctx.trapStateTab(mid, root, a);
cases.push({name:"tab-middle", ok: midTrapped === false && mid.prevented === false, trapped: midTrapped, prevented: mid.prevented});
run("tab-last", false, b, true, "a");
run("shift-first", true, a, true, "b");
run("tab-outside", false, el(), true, "a");
run("shift-outside", true, el(), true, "b");
const empty = { querySelectorAll() { return []; }, contains() { return false; } };
const ee = ev(false);
const emptyTrapped = ctx.trapStateTab(ee, empty, null);
cases.push({name:"empty", ok: emptyTrapped === true && ee.prevented === true, trapped: emptyTrapped, prevented: ee.prevented});
const notTab = { key:"Escape", shiftKey:false, prevented:false, preventDefault() { this.prevented = true; } };
const escapeIgnored = ctx.trapStateTab(notTab, root, b);
cases.push({name:"escape-not-tab", ok: escapeIgnored === false && notTab.prevented === false});
cases.push({name:"focusable-order", ok: JSON.stringify(focusable) === JSON.stringify(["a","b"]), focusable});
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	var rows []struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("decode %v: %s", err, raw)
	}
	if len(rows) == 0 {
		t.Fatal("no focus cases")
	}
	for _, row := range rows {
		if !row.OK {
			t.Errorf("focus case %s failed: %s", row.Name, raw)
		}
	}
}
