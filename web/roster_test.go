package web

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// Roster structure, menu, states, archive toast, mark contrast, and the
// polish items that landed with the roster (sheet header, log title, desktop
// focus, thread column). Node runs the pure helpers between the markers.

func TestRosterStatic(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		`<h1>Bots</h1>`,
		`.roster-head { height: 64px;`,
		`aria-label="Roster menu"`,
		`aria-haspopup="menu"`,
		`aria-expanded="false"`,
		`aria-label="New bot"`,
		`id="roster-menu"`,
		`role="menuitemcheckbox"`,
		`id="menu-show-hidden"`,
		`>Show hidden`,
		`id="menu-archived"`,
		`id="menu-log">Log</button>`,
		`id="appearance-label">Appearance</div>`,
		`id="theme-seg" role="radiogroup"`,
		`aria-label="Appearance"`,
		`role="radio"`,
		`data-theme="system"`,
		`data-theme="light"`,
		`data-theme="dark"`,
		`el("div", "roster-group", "Pinned")`,
		`el("div", "roster-group", "All bots")`,
		`el("button", "roster-back", "‹ Archived")`,
		`el("button", "ghost unarchive", "Unarchive")`,
		`"No bots yet."`,
		`"Every bot is hidden."`,
		`"No archived bots."`,
		`el("p", "roster-error", ROSTER_ERROR_NOTE)`,
		"  $(\"#thread-label\").textContent = \"\";\n  $(\"#run-note\").hidden = true;",
		`Can't reach the daemon. Retrying…`,
		"reconnecting…",
		"daemon unreachable",
		` · connected`,
		`for (let i = 0; i < 3; i++)`,
		`el("div", "skel-row")`,
		`.skel-mark { width: 28px; height: 28px; border-radius: 99px; background: var(--surface-2);`,
		`.skel-line { height: 10px; border-radius: 6px; background: var(--surface-2);`,
		`.state-sheet, .state-backdrop, .toast, .skel-mark, .skel-line { transition: none; animation: none; }`,
		`"Current colour " + color`,
		`id="mark-advisory"`,
		`contrastAdvisories(state.mark.color)`,
		`This colour is hard to see in dark mode. Pick a preset to fix it.`,
		`This colour is hard to see in light mode. Pick a preset to fix it.`,
		`function noteRunStarted`,
		`if (noteRunStarted(state.bots, state.botId)) renderBots();`,
		`event === "status"`,
		`if (state.streaming && b.status !== "running") b.status = "running";`,
		`if (state.streaming && state.botId)`,
		`const ARCHIVE_TOAST_MS = 6000;`,
		`function archiveToastText`,
		`setTimeout(dismissToast, ARCHIVE_TOAST_MS)`,
		`el("button", "ghost", "Undo")`,
		`id="toast" class="toast" role="status" aria-live="polite"`,
		`document.title = "Log — Local Grok Bots"`,
		`function desktopPaneFocusTarget`,
		`focusPane("chat")`,
		`focusPane("profile")`,
		`focusPane("log")`,
		`.state-sheet .sheet-head { height: 56px; }`,
		`.roster-head, .thread-bar, .solo-bar { height: 56px; }`,
		`max-width: none;`,
		`max-width: 800px;`,
		`<form class="composer" id="composer" hidden>`,
		`id="menu-btn" hidden`,
		`.composer[hidden], #menu-btn[hidden] { display: none !important; }`,
		`id="create-sheet"`,
		`aria-labelledby="create-title"`,
		`openBot(bot.id)`,
		`function rosterRowMove`,
		`$("#bot-list").addEventListener("keydown"`,
		`el("small", "bot-attn", words)`,
		`button.bot.is-selected { background: var(--sel); }`,
		`.bot.dim { opacity: .6; }`,
		`.status.running .dot { background: var(--status-running); box-shadow: 0 0 0 3px var(--accent-soft); }`,
		`.status.needs { color: var(--attention-text); font-weight: 600; }`,
		`.perm-badge {`,
		`height: 56px; max-height: 56px;`,
		`localStorage.setItem("lgb.theme", mode)`,
		`localStorage.getItem("lgb.theme")`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	for _, s := range []string{
		`id="theme-select"`,
		`<option value="system">System</option>`,
		`"Custom " + color`,
		`confirm("Archive`,
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has %q", s)
		}
	}

	roster := section(t, src, `id="view-bots"`, `id="view-chat"`)
	if strings.Contains(roster, "<form") || strings.Contains(roster, "create-form") {
		t.Error("roster list still contains the create form")
	}
	if !strings.Contains(roster, `<footer class="roster-foot"><p id="health">`) {
		t.Error("health must stay in the roster footer")
	}
	foot := roster[strings.Index(roster, "<footer"):strings.Index(roster, "</footer>")]
	for _, bad := range []string{"theme", "Appearance", "<select", "New bot"} {
		if strings.Contains(foot, bad) {
			t.Errorf("roster footer still contains %q", bad)
		}
	}

	thread := section(t, src, `id="thread"`, `id="view-profile"`)
	bar := strings.Index(thread, `class="thread-bar"`)
	col := strings.Index(thread, `class="thread-col"`)
	msgs := strings.Index(thread, `id="msgs"`)
	composer := strings.Index(thread, `id="composer"`)
	if bar < 0 || col < 0 || msgs < 0 || composer < 0 || !(bar < col && col < msgs && msgs < composer) {
		t.Fatalf("thread header must span the pane and the column must hold messages and the composer")
	}

	openBot := between(t, src, "async function openBot", "async function refreshBot")
	firstFocus := strings.Index(openBot, `focusPane("chat")`)
	refresh := strings.Index(openBot, "await refreshBot()")
	if firstFocus < 0 || refresh < 0 || firstFocus > refresh {
		t.Fatal("openBot must focus the thread heading before refresh replaces the roster row")
	}
	if strings.Count(openBot, `focusPane("chat")`) < 2 {
		t.Fatal("openBot must focus the thread heading again after refresh")
	}
	openLog := between(t, src, "function openLog", "function setTitle")
	if strings.Index(openLog, `setView("log")`) > strings.Index(openLog, "setTitle()") || !strings.Contains(openLog, `focusPane("log")`) {
		t.Fatalf("openLog must set the log view, then the title, then focus: %s", openLog)
	}
	reveal := between(t, src, "function revealLevel", "function openLog")
	if !strings.Contains(reveal, "return openLog(false)") {
		t.Fatal("a direct #log link must open the log view")
	}
	setTitle := between(t, src, "function setTitle()", "function goHome")
	if !strings.Contains(setTitle, `state.view === "log"`) || !strings.Contains(setTitle, `"Log — Local Grok Bots"`) {
		t.Fatal("setTitle must keep the log title while the log view is showing")
	}
	openProfile := between(t, src, "async function openProfile", "async function loadRoutines")
	if strings.Index(openProfile, `setView("profile")`) > strings.Index(openProfile, `focusPane("profile")`) {
		t.Fatal("openProfile must enter the profile view before focusing its heading")
	}

	wide := strings.Join(mediaBodies(t, src, "@media (max-width: 979px)"), "\n")
	head, ok := ruleBody(wide, ".state-sheet .sheet-head")
	if !ok || !strings.Contains(head, "height: 56px") {
		t.Fatalf("sheet header below 980px = %q", head)
	}
	if !strings.Contains(wide, ".roster-head, .thread-bar, .solo-bar { height: 56px; }") {
		t.Error("roster, thread, and solo bars must be 56px below 980px")
	}
	phone := strings.Join(mediaBodies(t, src, "@media (max-width: 540px)"), "\n")
	if strings.Contains(phone, ".state-sheet .sheet-head") {
		t.Error("sheet header height must not be limited to the 540px breakpoint")
	}
	desk, ok := ruleBody(src, ".state-sheet .sheet-head")
	if !ok || !strings.Contains(desk, "height: 64px") {
		t.Fatalf("desktop sheet header = %q", desk)
	}
	row, ok := ruleBody(src, "button.bot")
	if !ok {
		t.Fatal("roster row rule missing")
	}
	for _, s := range []string{"min-height: 64px", "padding: 10px 12px", "gap: 12px", "border: 0", "border-radius: 14px"} {
		if !strings.Contains(row, s) {
			t.Errorf("roster row missing %s in %q", s, row)
		}
	}
	footRule, ok := ruleBody(src, ".roster-foot")
	if !ok || !strings.Contains(footRule, "height: 56px") || !strings.Contains(footRule, "max-height: 56px") {
		t.Fatalf("roster footer = %q", footRule)
	}
	colRule, ok := ruleBody(src, ".thread-col")
	if !ok || !strings.Contains(colRule, "max-width: 800px") || !strings.Contains(colRule, "margin-left: auto") {
		t.Fatalf("thread column = %q", colRule)
	}

	urls := strings.ReplaceAll(src, "http://www.w3.org/2000/svg", "")
	for _, scheme := range []string{"http://", "https://"} {
		if i := strings.Index(urls, scheme); i >= 0 {
			t.Errorf("remote asset reference near %q", urls[i:min(i+60, len(urls))])
		}
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*\ssrc\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)<link[^>]*\shref\s*=\s*["']https?:`),
		regexp.MustCompile(`(?i)@import\s+["']?https?:`),
		regexp.MustCompile(`(?i)url\(\s*["']?https?:`),
	}
	for _, re := range patterns {
		if loc := re.FindStringIndex(src); loc != nil {
			t.Errorf("remote asset reference %q", src[loc[0]:loc[1]])
		}
	}
}

func TestRosterLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	src := string(IndexHTML)
	var b strings.Builder
	for _, pair := range [][2]string{
		{"// health:begin", "// health:end"},
		{"// roster-logic:begin", "// roster-logic:end"},
		{"// contrast:begin", "// contrast:end"},
		{"// runstate:begin", "// runstate:end"},
		{"// roster-keys:begin", "// roster-keys:end"},
		{"// menu-keys:begin", "// menu-keys:end"},
		{"// pane-focus:begin", "// pane-focus:end"},
		{"// toast:begin", "// toast:end"},
	} {
		b.WriteString(between(t, src, pair[0], pair[1]))
		b.WriteString("\n")
	}
	snippet, err := json.Marshal(b.String())
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\n" + [
  "healthView", "archivedMenuLabel", "ROSTER_ERROR_NOTE", "nextBackoff",
  "rosterListMode", "approvalWords",
  "contrastAdvisories", "markContrastFails", "contrastRatio",
  "noteRunStarted",
  "rosterRowMove", "menuKeyAction",
  "desktopPaneFocusTarget",
  "archiveToastText", "ARCHIVE_TOAST_MS"
].map(function (n) { return "this." + n + "=" + n + ";"; }).join("\n"), ctx);
const cases = [];
function check(name, ok, extra) { cases.push(Object.assign({name: name, ok: !!ok}, extra || {})); }
const dark = "This colour is hard to see in dark mode. Pick a preset to fix it.";
const light = "This colour is hard to see in light mode. Pick a preset to fix it.";
function hv(phase, version) { return ctx.healthView(phase, version); }
check("health-retry", hv("retrying").text === "reconnecting…" && hv("retrying").dot === "retry");
check("health-loading", hv("loading").text === "reconnecting…" && hv("loading").dot === "retry");
check("health-down", hv("down").text === "daemon unreachable" && hv("down").dot === "down");
check("health-ok", hv("ok", "1.2.3").text === "daemon 1.2.3 · connected" && hv("ok", "1.2.3").dot === "ok");
check("error-note", ctx.ROSTER_ERROR_NOTE === "Can't reach the daemon. Retrying…");
check("arch-blank", ctx.archivedMenuLabel(null) === "" && ctx.archivedMenuLabel(undefined) === "" && ctx.archivedMenuLabel(-1) === "" && ctx.archivedMenuLabel(NaN) === "");
check("arch-zero", ctx.archivedMenuLabel(0) === "Archived (0) ›");
check("arch-two", ctx.archivedMenuLabel(2) === "Archived (2) ›");
check("backoff", ctx.nextBackoff(0) === 1000 && ctx.nextBackoff(1000) === 2000 && ctx.nextBackoff(8000) === 15000 && ctx.nextBackoff(15000) === 15000);
check("mode-loading", ctx.rosterListMode(false, false, "retrying") === "loading");
check("mode-error-down", ctx.rosterListMode(false, true, "down") === "error" && ctx.rosterListMode(true, true, "down") === "error");
check("mode-error-retry", ctx.rosterListMode(false, true, "retrying") === "error" && ctx.rosterListMode(true, true, "retrying") === "error");
check("mode-ready", ctx.rosterListMode(true, false, "ok") === "ready" && ctx.rosterListMode(true, false, "retrying") === "ready");
check("approvals", ctx.approvalWords(1) === "1 approval waiting" && ctx.approvalWords(4) === "4 approvals waiting");
const preset = ctx.contrastAdvisories("#4C77DD");
check("preset-passes", preset.length === 0 && ctx.markContrastFails("#4C77DD", "light") === false && ctx.markContrastFails("#4C77DD", "dark") === false, {preset: preset});
const legacy = ctx.contrastAdvisories("#1d4e89");
check("legacy-dark", legacy.length === 1 && legacy[0] === dark && ctx.markContrastFails("#1d4e89", "light") === false, {legacy: legacy});
const white = ctx.contrastAdvisories("#ffffff");
check("white-light", white.length === 1 && white[0] === light, {white: white});
const black = ctx.contrastAdvisories("#000000");
check("black-dark", black.length === 1 && black[0] === dark, {black: black});
let threw = false;
try { ctx.contrastAdvisories("nope"); ctx.contrastAdvisories(null); ctx.contrastAdvisories("#zz"); } catch (e) { threw = true; }
check("contrast-safe", !threw && ctx.contrastAdvisories("nope").length === 0);
const bots = [{id: "a", status: "idle"}, {id: "b", status: "paused"}];
check("run-flips", ctx.noteRunStarted(bots, "a") === true && bots[0].status === "running" && bots[1].status === "paused");
check("run-keeps", ctx.noteRunStarted(bots, "a") === false && ctx.noteRunStarted(bots, "missing") === false && ctx.noteRunStarted(null, "a") === false);
const rows = ["r0", "r1", "r2"];
check("row-down-start", JSON.stringify(ctx.rosterRowMove("ArrowDown", rows, null)) === JSON.stringify({focusIndex: 0}));
check("row-down-end", JSON.stringify(ctx.rosterRowMove("ArrowDown", rows, "r2")) === JSON.stringify({focusIndex: 2}));
check("row-up-start", JSON.stringify(ctx.rosterRowMove("ArrowUp", rows, null)) === JSON.stringify({focusIndex: 2}));
check("row-up-end", JSON.stringify(ctx.rosterRowMove("ArrowUp", rows, "r0")) === JSON.stringify({focusIndex: 0}));
check("row-enter", JSON.stringify(ctx.rosterRowMove("Enter", rows, "r1")) === JSON.stringify({openIndex: 1}));
check("row-enter-none", ctx.rosterRowMove("Enter", rows, "nope") === null && ctx.rosterRowMove("Tab", rows, "r0") === null);
const items = ["a", "b", "c"];
check("menu-esc", JSON.stringify(ctx.menuKeyAction("Escape", items, 1)) === JSON.stringify({close: true, focusTrigger: true}));
check("menu-tab", JSON.stringify(ctx.menuKeyAction("Tab", items, 1)) === JSON.stringify({close: true}));
check("menu-down", JSON.stringify(ctx.menuKeyAction("ArrowDown", items, 2)) === JSON.stringify({move: 0}));
check("menu-up", JSON.stringify(ctx.menuKeyAction("ArrowUp", items, 0)) === JSON.stringify({move: 2}));
check("menu-enter", JSON.stringify(ctx.menuKeyAction("Enter", items, 1)) === JSON.stringify({activate: 1}));
check("menu-other", ctx.menuKeyAction("x", items, 0) === null);
function pane(name, wide) { return ctx.desktopPaneFocusTarget(name, wide); }
check("pane-chat", JSON.stringify(pane("chat", true)) === JSON.stringify({sel: "#thread-name", tabindex: -1}));
check("pane-profile", JSON.stringify(pane("profile", true)) === JSON.stringify({sel: "#profile-heading", tabindex: -1}));
check("pane-log", JSON.stringify(pane("log", true)) === JSON.stringify({sel: "#view-log h2.solo-title", tabindex: -1}));
check("pane-narrow", pane("chat", false) === null && pane("bots", true) === null);
check("toast-text", ctx.archiveToastText("Ada") === "Archived Ada · Undo" && ctx.ARCHIVE_TOAST_MS === 6000);
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func section(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	j := strings.Index(src, end)
	if i < 0 || j < i {
		t.Fatalf("section %s … %s missing", start, end)
	}
	return src[i:j]
}
