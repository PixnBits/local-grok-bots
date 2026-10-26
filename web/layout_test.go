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
vm.runInContext(snippet + "\nthis.parseLevel=parseLevel; this.levelURL=levelURL; this.backAction=backAction; this.parentLevel=parentLevel; this.botFromPathname=botFromPathname; this.historyStamp=historyStamp;", ctx);
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
eq("stamp-profile", ctx.historyStamp(null, "/bots/abc", "#profile", ""), {op:"replace", view:"profile", bot:"abc"});
eq("stamp-log", ctx.historyStamp(null, "/bots/abc", "#log", ""), {op:"replace", view:"log", bot:"abc"});
eq("stamp-log-home", ctx.historyStamp(null, "/", "#log", ""), {op:"replace", view:"log", bot:null});
eq("stamp-keep", ctx.historyStamp({lgb:1, view:"chat", bot:"abc", idx:2}, "/bots/abc", "#profile", ""), null);
eq("stamp-pop-null", ctx.historyStamp(null, "/bots/abc", "", ""), {op:"replace", view:"chat", bot:"abc"});
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

func TestProfileMobileJustifyStart(t *testing.T) {
	src := string(IndexHTML)
	blocks := mediaBodies(t, src, `@media (max-width: 979px)`)
	var mobile string
	for _, block := range blocks {
		if body, ok := ruleBody(block, ".profile-layout"); ok {
			mobile = body
		}
	}
	if mobile == "" {
		t.Fatal("max-width:979px block has no .profile-layout rule")
	}
	if !strings.Contains(mobile, "justify-content: flex-start") {
		t.Fatalf(".profile-layout in 979px block = %q", mobile)
	}
	if strings.Contains(mobile, "justify-content: center") {
		t.Fatalf("mobile .profile-layout still centers: %q", mobile)
	}
	base, ok := ruleBody(src, ".profile-layout")
	if !ok || !strings.Contains(base, "justify-content: center") {
		t.Fatalf("desktop .profile-layout lost justify-content: center: %q", base)
	}
}

func TestMenuButtonPattern(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	snippet, err := json.Marshal(between(t, src, "// menu:begin", "// menu:end"))
	if err != nil {
		t.Fatal(err)
	}
	menuClick := between(t, src, `$("#bot-menu").addEventListener("click"`, "async function setArchived")
	if !strings.Contains(menuClick, "closeMenu()") {
		t.Error("activating a menu item must close the menu")
	}
	if strings.Contains(between(t, src, "// menu:begin", "// menu:end"), "hidden = false") {
		t.Error("menu close path reopens the popup")
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\nthis.restoreStateFocus=restoreStateFocus; this.handleMenuEscape=handleMenuEscape; this.handleMenuFocusOut=handleMenuFocusOut;", ctx);
function make(match) {
  return {
    match: match,
    hidden: false,
    attrs: {},
    children: [],
    parent: null,
    focused: 0,
    focusArg: null,
    setAttribute(k, v) { this.attrs[k] = String(v); },
    focus(arg) { this.focused++; this.focusArg = arg || null; },
    matches(sel) { return sel === this.match; },
    closest(sel) {
      let cur = this;
      while (cur) {
        if (cur.matches && cur.matches(sel)) return cur;
        cur = cur.parent;
      }
      return null;
    },
    querySelector(sel) {
      const walk = (node) => {
        for (const c of node.children) {
          if (c.matches && c.matches(sel)) return c;
          const found = walk(c);
          if (found) return found;
        }
        return null;
      };
      return walk(this);
    },
    contains(node) {
      const walk = (cur) => {
        if (!cur) return false;
        if (cur === node) return true;
        for (const c of cur.children || []) if (walk(c)) return true;
        return false;
      };
      return walk(this);
    }
  };
}
function link(parent, child) {
  child.parent = parent;
  parent.children.push(child);
  return child;
}
function build(triggerMatch) {
  const menu = make(".menu");
  const trigger = link(menu, make(triggerMatch || "[aria-haspopup='menu']"));
  trigger.attrs["aria-expanded"] = "true";
  const pop = link(menu, make(".menu-pop"));
  pop.hidden = true;
  const item = link(pop, make("[role='menuitem']"));
  return { menu, trigger, pop, item };
}
const cases = [];
function check(name, ok, extra) {
  cases.push(Object.assign({ name, ok }, extra || {}));
}
ctx.document = { contains() { return true; } };
ctx.setTimeout = (fn) => { fn(); };
const thread = build("[aria-haspopup='menu']");
ctx.stateReturnFocus = thread.item;
ctx.restoreStateFocus();
check("close-focuses-trigger",
  thread.trigger.focused === 1 && thread.item.focused === 0 && thread.pop.hidden === true && thread.trigger.attrs["aria-expanded"] === "false",
  { focused: thread.trigger.focused, item: thread.item.focused, hidden: thread.pop.hidden, expanded: thread.trigger.attrs["aria-expanded"] });
const profile = build("[aria-haspopup='menu']");
profile.trigger.id = "profile-menu";
ctx.stateReturnFocus = profile.item;
ctx.restoreStateFocus();
check("close-profile-trigger",
  profile.trigger.focused === 1 && profile.pop.hidden === true && profile.trigger.attrs["aria-expanded"] === "false");
const chip = make("#state-chip");
ctx.stateReturnFocus = chip;
ctx.restoreStateFocus();
check("close-chip", chip.focused === 1 && chip.hidden !== true);
const open = build();
open.pop.hidden = false;
let behind = false;
const esc = {
  key: "Escape",
  preventDefault() { this.prevented = true; },
  stopPropagation() { this.stopped = true; },
  stopImmediatePropagation() { this.immediate = true; }
};
const handled = ctx.handleMenuEscape(esc, open.pop);
if (!esc.immediate) behind = true;
check("escape-closes",
  handled === true && esc.prevented === true && esc.stopped === true && esc.immediate === true && behind === false && open.pop.hidden === true && open.trigger.focused === 1 && open.trigger.attrs["aria-expanded"] === "false",
  { handled, prevented: esc.prevented, hidden: open.pop.hidden, focused: open.trigger.focused, behind });
const quiet = build();
quiet.pop.hidden = true;
const escClosed = { key: "Escape", preventDefault() { this.prevented = true; }, stopPropagation() {}, stopImmediatePropagation() {} };
check("escape-closed-menu", ctx.handleMenuEscape(escClosed, quiet.pop) === false && escClosed.prevented !== true);
const tab = build();
tab.pop.hidden = false;
const outside = make("#elsewhere");
const left = ctx.handleMenuFocusOut({ relatedTarget: outside }, tab.pop);
check("focusout-closes", left === true && tab.pop.hidden === true && tab.trigger.attrs["aria-expanded"] === "false");
const stay = build();
stay.pop.hidden = false;
const stayed = ctx.handleMenuFocusOut({ relatedTarget: stay.trigger }, stay.pop);
check("focusout-trigger", stayed === false && stay.pop.hidden === false);
const inside = build();
inside.pop.hidden = false;
const itemStay = ctx.handleMenuFocusOut({ relatedTarget: inside.item }, inside.pop);
check("focusout-item", itemStay === false && inside.pop.hidden === false);
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func TestProfileSoloHeading(t *testing.T) {
	src := string(IndexHTML)
	start := strings.Index(src, `<section class="view" id="view-profile">`)
	if start < 0 {
		t.Fatal("profile view missing")
	}
	rest := src[start:]
	end := strings.Index(rest, `<div class="profile-layout">`)
	if end < 0 {
		t.Fatal("profile layout missing")
	}
	bar := rest[:end]
	hStart := strings.Index(bar, "<h2")
	if hStart < 0 {
		t.Fatal("profile solo bar missing h2")
	}
	openEnd := strings.Index(bar[hStart:], ">")
	if openEnd < 0 {
		t.Fatal("profile h2 tag unclosed")
	}
	open := bar[hStart : hStart+openEnd]
	for _, s := range []string{`class="solo-id"`, `id="profile-heading"`, `tabindex="-1"`} {
		if !strings.Contains(open, s) {
			t.Errorf("profile heading %q missing %s", open, s)
		}
	}
	close := strings.Index(bar[hStart:], "</h2>")
	if close < 0 {
		t.Fatal("profile h2 not closed")
	}
	inner := bar[hStart+openEnd : hStart+close]
	if !strings.Contains(inner, `id="profile-head-name"`) {
		t.Errorf("profile heading missing name: %s", inner)
	}
	if !strings.Contains(src, `if (name === "profile") return { sel: "#profile-heading", tabindex: -1 };`) {
		t.Error(`drill focus target for profile must be "#profile-heading"`)
	}
}

func TestProfileScrollAndDrillFocus(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	open := between(t, src, "async function openProfile", "async function loadRoutines")
	if !strings.Contains(open, `resetScrollTops(document.querySelectorAll(".profile-layout, .profile-col"))`) {
		t.Fatal("openProfile must reset profile scroll containers")
	}
	setView := between(t, src, "function setView(name)", `$("#log-toggle")`)
	if !strings.Contains(setView, "shouldFocusDrill(prev, name, wide)") {
		t.Fatal("setView must focus a new narrow drill level")
	}
	hash := between(t, src, `addEventListener("hashchange"`, `addEventListener("popstate"`)
	if !strings.Contains(hash, "ensureHistory()") || !strings.Contains(hash, "revealLevel") {
		t.Fatal("hashchange must restamp and reveal")
	}
	pop := between(t, src, `addEventListener("popstate"`, "async function openBot")
	if !strings.Contains(pop, "ensureHistory()") {
		t.Fatal("popstate must restamp a null history.state")
	}
	scroll, err := json.Marshal(between(t, src, "// scroll:begin", "// scroll:end"))
	if err != nil {
		t.Fatal(err)
	}
	drill, err := json.Marshal(between(t, src, "// drill:begin", "// drill:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const ctx = {};
vm.createContext(ctx);
vm.runInContext(` + string(scroll) + ` + "\n" + ` + string(drill) + ` + "\nthis.resetScrollTops=resetScrollTops; this.shouldFocusDrill=shouldFocusDrill; this.drillFocusTarget=drillFocusTarget; this.applyDrillFocus=applyDrillFocus; this.focusDrillView=focusDrillView;", ctx);
const cases = [];
function check(name, ok, extra) { cases.push(Object.assign({name, ok}, extra || {})); }
const layout = { scrollTop: 480 };
const col = { scrollTop: 220 };
ctx.resetScrollTops([layout, col, null]);
check("scroll-reset", layout.scrollTop === 0 && col.scrollTop === 0, { layout: layout.scrollTop, col: col.scrollTop });
check("home-load", ctx.shouldFocusDrill("bots", "bots", false) === false);
check("deep-thread", ctx.shouldFocusDrill("bots", "chat", false) === true);
check("wide-thread", ctx.shouldFocusDrill("bots", "chat", true) === false);
check("open-profile", ctx.shouldFocusDrill("chat", "profile", false) === true);
check("open-log", ctx.shouldFocusDrill("chat", "log", false) === true);
check("back-roster", ctx.shouldFocusDrill("profile", "bots", false) === true);
check("same-profile", ctx.shouldFocusDrill("profile", "profile", false) === false);
const want = {
  bots: "#view-bots h1",
  chat: "#thread-name",
  profile: "#profile-heading",
  log: "#view-log h2.solo-title"
};
for (const name of Object.keys(want)) {
  const spec = ctx.drillFocusTarget(name, false);
  check("target-"+name, !!spec && spec.sel === want[name] && spec.tabindex === -1, spec);
}
check("target-wide", ctx.drillFocusTarget("chat", true) === null);
const el = { tabIndex: 0, focused: 0, focusArg: null, focus(arg) { this.focused++; this.focusArg = arg; } };
check("apply-focus", ctx.applyDrillFocus(el, -1) === true && el.tabIndex === -1 && el.focused === 1 && el.focusArg && el.focusArg.preventScroll === true);
const found = { tabIndex: 0, focused: 0, focusArg: null, focus(arg) { this.focused++; this.focusArg = arg; } };
check("focus-view", ctx.focusDrillView("chat", false, (sel) => sel === "#thread-name" ? found : null) === true && found.tabIndex === -1 && found.focusArg.preventScroll === true);
check("focus-wide", ctx.focusDrillView("chat", true, () => found) === false);
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func mediaBodies(t *testing.T, src, header string) []string {
	t.Helper()
	var blocks []string
	from := 0
	for {
		i := strings.Index(src[from:], header)
		if i < 0 {
			break
		}
		i += from
		rest := src[i+len(header):]
		brace := strings.Index(rest, "{")
		if brace < 0 {
			t.Fatalf("media %s missing body", header)
		}
		start := i + len(header) + brace + 1
		depth := 1
		p := start
		for p < len(src) && depth > 0 {
			switch src[p] {
			case '{':
				depth++
			case '}':
				depth--
			}
			p++
		}
		if depth != 0 {
			t.Fatalf("unbalanced %s", header)
		}
		blocks = append(blocks, src[start:p-1])
		from = p
	}
	if len(blocks) == 0 {
		t.Fatalf("no %s blocks", header)
	}
	return blocks
}

func ruleBody(block, selector string) (string, bool) {
	re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(selector) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(block)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func assertCases(t *testing.T, raw string) {
	t.Helper()
	var rows []struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
	}
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatalf("decode %v: %s", err, raw)
	}
	if len(rows) == 0 {
		t.Fatal("no cases")
	}
	for _, row := range rows {
		if !row.OK {
			t.Errorf("case %s failed: %s", row.Name, raw)
		}
	}
}
