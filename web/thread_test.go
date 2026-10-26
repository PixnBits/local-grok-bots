package web

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Thread, Stop, cards, roster focus after archive, theme radiogroup keys,
// and the unreachable retry. Static pins lock the copy the spec names.
// Node runs the pure helpers between the thread-logic markers.

func TestThreadStatic(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		`aria-label="Stop run"`,
		"Stop · Esc",
		`"/runs/" + encodeURIComponent(runId) + "/cancel"`,
		"Stopped by you",
		"your queued message starts the next run",
		"Couldn't stop the run. The daemon didn't respond.",
		"Waiting for your approval",
		"Stopping…",
		"Stopping run",
		"Run stopped",
		"Queued · the bot reads this before its next step",
		"QUESTION FROM ",
		"APPROVAL REQUIRED · GIT_PUSH",
		"APPROVAL REQUIRED · CREATE_PR",
		"PERMISSION NEEDED · EXITPLANMODE",
		"Cancelled · run stopped by you",
		"Allowed once · `",
		"Allowed for session · `",
		"Denied · `",
		"Expired · denied after ",
		"Denied automatically when the timer runs out.",
		"Body preview · clipped at 2,000 characters",
		"Every push asks. Session approval does not apply.",
		"Every pull request asks. Nothing is sent to GitHub until you allow it.",
		"Couldn't send your answer. The daemon didn't respond. Try again.",
		"Stopped after denial.",
		"Open in Log",
		"Try again",
		"Stopped after 8 tool rounds. Continue picks up the same work for 8 more.",
		"Archived. Routines are paused and new messages wait until it is restored.",
		"Enter to send · Shift+Enter for a new line · the bot reads follow-ups while it works",
		"Enter to send · Esc to stop · the bot reads follow-ups while it works",
		"Retry now",
		"Retrying…",
		`id="a11y-status"`,
		`aria-live="polite"`,
		`id="stop-btn"`,
		`id="menu-stop"`,
		`data-act="stop"`,
		"Log for ",
		`id="theme-seg"`,
		`role="radiogroup"`,
		`tabindex="0">System</button>`,
		`tabindex="-1">Light</button>`,
		`tabindex="-1">Dark</button>`,
		"width: 7px; height: 15px;",
		".state-chip { height: 32px; min-height: 32px; gap: 6px; padding: 0 8px; }",
		`retry.id = "retry-now"`,
		"function archiveFocusTarget",
		"function themeRadioKey",
		"function retryTrigger",
		"// thread-logic:begin",
		"// thread-logic:end",
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	urls := strings.ReplaceAll(src, "http://www.w3.org/2000/svg", "")
	for _, scheme := range []string{"http://", "https://"} {
		if i := strings.Index(urls, scheme); i >= 0 {
			t.Errorf("external URL near %q", urls[i:min(i+48, len(urls))])
		}
	}
	i := strings.Index(src, "// perm:begin")
	j := strings.Index(src, "// perm:end")
	if i < 0 || j < i {
		t.Fatal("permission markers missing")
	}
	if strings.Contains(src[i:j], "innerHTML") {
		t.Error("permission card writes with innerHTML")
	}
}

// Phone header and thread details found in the live check.
func TestThreadPolish(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		// The chip's segments must not pick up the theme control's .seg box.
		`.state-chip .chip-seg {`,
		`el("span", "chip-seg"`,
		// Phone chip is icons and numbers only, as in 09b.
		`.state-chip .chip-chev { display: none; }`,
		// Tool summary stays one line; the names truncate.
		`.tsum .names { min-width: 0; overflow: hidden; text-overflow: ellipsis; }`,
		// The caret follows the last text block of the live bubble.
		"placeCaret(bubble, text);",
		// The composer pill carries focus; the textarea ring is transparent
		// (still shown in forced-colors mode).
		`.composer textarea:focus-visible { outline: 2px solid transparent; outline-offset: 0; box-shadow: none; }`,
		// When Retry now goes away on recovery, focus lands on the Bots heading.
		`if (key === rosterFocusKey("retry", "")) {`,
		// Stop from the button (click, Space, Enter) or the ⋯ item returns
		// focus to the composer. Esc in the composer already leaves it there.
		`function focusComposerAfterStop()`,
		`input.focus({ preventScroll: true })`,
		`focusComposerAfterStop();`,
		// follow switches the hint to the running copy as soon as the phase does.
		"state.stop = reduceStop(state.stop || freshStop(), { type: \"run\", runId: runId });\n  syncComposer();",
		// Leaving running or stopping restores the idle hint.
		"syncStopButton();\n  syncComposer();",
	} {
		if !strings.Contains(src, s) {
			t.Errorf("missing %q", s)
		}
	}
	if strings.Contains(src, `el("span", "seg"`) {
		t.Error("state chip segment still uses the .seg class")
	}
}

func TestThreadLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// thread-logic:begin", "// thread-logic:end"))
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\n" + [
  "freshStop", "reduceStop", "stoppedLineText", "clockLabel", "durationLabel",
  "shouldClearQueued", "queuedClearOnThread", "escStopsRun", "workingIndicatorText",
  "threadSubline", "stateChipName", "composerHint", "composerPlaceholder",
  "cardEyebrow", "cardTitle", "cardRecordText", "recordKind", "countdownAnnounce",
  "archiveFocusTarget", "themeRadioKey", "retryTrigger", "toolCallLabel",
  "partialsToShow", "mergeRunRecords", "runRecordKey",
  "STOP_TIMEOUT_MS", "QUEUED_CAPTION", "STOP_FAILED_NOTE", "HINT_IDLE", "HINT_RUNNING"
].map(function (n) { return "this." + n + "=" + n + ";"; }).join("\n"), ctx);
const cases = [];
function check(name, ok) { cases.push({name: name, ok: !!ok}); }
function phase(s) { return s && s.phase; }
let s = ctx.freshStop();
check("stop-timeout", ctx.STOP_TIMEOUT_MS === 10000);
check("idle", phase(s) === "idle" && s.line === "" && s.note === "");
s = ctx.reduceStop(s, {type: "press", now: 0});
check("press-idle", phase(s) === "idle");
s = ctx.reduceStop(s, {type: "run", runId: "r1"});
check("running", phase(s) === "running" && s.runId === "r1" && s.pressed === false);
s = ctx.reduceStop(s, {type: "press", now: 1000, runId: "r1", queued: false});
check("stopping", phase(s) === "stopping" && s.pressed === true && s.since === 1000);
const held = ctx.reduceStop(s, {type: "tick", now: 10999});
check("tick-holds", phase(held) === "stopping" && held.note === "");
const timed = ctx.reduceStop(s, {type: "tick", now: 11000});
check("tick-fails", phase(timed) === "running" && timed.note === "stop-failed" && timed.pressed === false);
const failed = ctx.reduceStop(s, {type: "cancel-error"});
check("cancel-error", phase(failed) === "running" && failed.note === "stop-failed");
const stay = ctx.reduceStop(s, {type: "cancel-result", status: "cancelled", streamEnded: false});
check("cancel-open", phase(stay) === "stopping" && stay.line === "" && stay.normalEnd === false);
const already = ctx.reduceStop(s, {type: "cancel-result", status: "cancelled", streamEnded: true});
check("cancel-finished", phase(already) === "idle" && already.normalEnd === true && already.line === "");
const done = ctx.reduceStop(s, {type: "cancel-result", status: "done"});
check("cancel-done", phase(done) === "idle" && done.normalEnd === true && done.line === "");
const stillRun = ctx.reduceStop(s, {type: "cancel-result", status: "running"});
check("cancel-running", phase(stillRun) === "running" && stillRun.note === "stop-failed");
const empty = ctx.reduceStop(s, {type: "cancel-result", status: ""});
check("cancel-empty", phase(empty) === "running" && empty.note === "stop-failed");
const runningQ = ctx.reduceStop(ctx.freshStop(), {type: "run", runId: "r1"});
const queuedStop = ctx.reduceStop(runningQ, {type: "press", now: 1000, runId: "r1", queued: true});
const stoppedQ = ctx.reduceStop(queuedStop, {type: "stream-done", status: "cancelled"});
check("stopped-queued", phase(stoppedQ) === "stopped" && stoppedQ.line === "queued");
const again = ctx.reduceStop(stoppedQ, {type: "stream-done", status: "cancelled"});
check("stopped-once", phase(again) === "stopped" && again.line === "queued");
const timeStop = ctx.reduceStop(s, {type: "stream-done", status: "cancelled"});
check("stopped-time", phase(timeStop) === "stopped" && timeStop.line === "time");
const notPressed = ctx.reduceStop(ctx.reduceStop(ctx.freshStop(), {type: "run", runId: "r1"}), {type: "stream-done", status: "cancelled"});
check("cancel-without-press", phase(notPressed) === "idle" && notPressed.normalEnd === true && notPressed.line === "");
const denial = ctx.reduceStop(s, {type: "stream-done", status: "stopped"});
check("denial-while-stopping", phase(denial) === "idle" && denial.normalEnd === true && denial.line === "");
const blankDone = ctx.reduceStop(s, {type: "stream-done", status: ""});
check("blank-done", phase(blankDone) === "idle" && blankDone.normalEnd === true);
const same = ctx.reduceStop(s, {type: "run", runId: "r1"});
check("run-same", phase(same) === "stopping" && same.runId === "r1");
const other = ctx.reduceStop(s, {type: "run", runId: "r2"});
check("run-other", phase(other) === "running" && other.runId === "r2" && other.pressed === false);
const restarted = ctx.reduceStop(timeStop, {type: "run", runId: "r9"});
check("run-after-stop", phase(restarted) === "running" && restarted.line === "" && restarted.runId === "r9");
check("line-queued", ctx.stoppedLineText(true, "1:00 PM") === "Stopped by you · your queued message starts the next run");
check("line-time", ctx.stoppedLineText(false, "1:00 PM") === "Stopped by you · 1:00 PM");
check("caption", ctx.QUEUED_CAPTION === "Queued · the bot reads this before its next step");
check("fail-note", ctx.STOP_FAILED_NOTE === "Couldn't stop the run. The daemon didn't respond.");
check("clear-reasons", ctx.shouldClearQueued("new-bot-token") === true && ctx.shouldClearQueued("stored-reply") === true && ctx.shouldClearQueued("done") === false && ctx.shouldClearQueued("error") === false && ctx.shouldClearQueued("stop") === false);
const u = {id: "u1", role: "user", created_at: "2020-01-01T00:00:10Z", run_id: "r1"};
const sameBot = {id: "b1", role: "bot", created_at: "2020-01-01T00:00:20Z", run_id: "r1"};
const nextBot = {id: "b2", role: "bot", created_at: "2020-01-01T00:00:20Z", run_id: "r2"};
const oldBot = {id: "b0", role: "bot", created_at: "2020-01-01T00:00:01Z", run_id: "r2"};
check("queue-next", ctx.queuedClearOnThread([], [u, nextBot], ["u1"], "r1") === true);
check("queue-same-run", ctx.queuedClearOnThread([], [u, sameBot], ["u1"], "r1") === false);
check("queue-seen", ctx.queuedClearOnThread([nextBot], [u, nextBot], ["u1"], "") === false);
check("queue-before", ctx.queuedClearOnThread([], [u, oldBot], ["u1"], "") === false);
check("queue-none", ctx.queuedClearOnThread([], [u], ["u1"], "r1") === false && ctx.queuedClearOnThread([], [u, nextBot], [], "r1") === false);
function esc(over) {
  const base = {key: "Escape", empty: true, inComposer: true, runActive: true, menuOpen: false, sheetOpen: false, dialogOpen: false};
  Object.keys(over || {}).forEach(function (k) { base[k] = over[k]; });
  return ctx.escStopsRun(base);
}
check("esc-ok", esc() === true);
check("esc-text", esc({empty: false}) === false);
check("esc-outside", esc({inComposer: false}) === false);
check("esc-menu", esc({menuOpen: true}) === false);
check("esc-sheet", esc({sheetOpen: true}) === false);
check("esc-dialog", esc({dialogOpen: true}) === false);
check("esc-idle", esc({runActive: false}) === false);
check("esc-other", esc({key: "Enter"}) === false);
check("work-plain", ctx.workingIndicatorText("working", "") === "Working");
check("work-tool", ctx.workingIndicatorText("working", "Bash") === "Working · Bash");
check("work-wait", ctx.workingIndicatorText("waiting", "Bash") === "Waiting for your approval · Bash");
check("work-wait-bare", ctx.workingIndicatorText("waiting", "") === "Waiting for your approval");
check("work-stop", ctx.workingIndicatorText("stopping", "Bash") === "Stopping…");
check("sub-idle", ctx.threadSubline("idle", "", "notes") === "idle · notes");
check("sub-run", ctx.threadSubline("running", "Bash", "notes") === "running · Bash · notes");
check("chip-zero", ctx.stateChipName(0, 0, 0) === "Bot state: 0 timers, 0 memory entries");
check("chip-one", ctx.stateChipName(1, 1, 0) === "Bot state: 1 timer, 1 memory entry");
check("chip-warn", ctx.stateChipName(2, 3, 1) === "Bot state: 2 timers, 3 memory entries, 1 warning");
check("chip-warns", ctx.stateChipName(0, 0, 2) === "Bot state: 0 timers, 0 memory entries, 2 warnings");
check("hint", ctx.composerHint(false) === ctx.HINT_IDLE && ctx.composerHint(true) === ctx.HINT_RUNNING);
check("ph-wide", ctx.composerPlaceholder("Recipe Helper", false) === "Message Recipe Helper");
check("ph-narrow", ctx.composerPlaceholder("Garden Notes", true) === "Message");
check("bash-label", ctx.toolCallLabel("Bash", {command: "git status"}) === "Bash(git status)");
check("eye-q", ctx.cardEyebrow({kind: "question", tool: "AskUserQuestion"}, "Recipe Helper") === "QUESTION FROM Recipe Helper");
check("eye-push", ctx.cardEyebrow({tool: "git_push"}, "") === "APPROVAL REQUIRED · GIT_PUSH");
check("eye-pr", ctx.cardEyebrow({tool: "create_pr"}, "") === "APPROVAL REQUIRED · CREATE_PR");
check("eye-plan", ctx.cardEyebrow({tool: "ExitPlanMode"}, "") === "PERMISSION NEEDED · EXITPLANMODE");
check("eye-bash", ctx.cardEyebrow({tool: "Bash"}, "") === "PERMISSION NEEDED");
function rec(kind, tool, time, dur) { return ctx.cardRecordText({kind: kind, toolLabel: tool, timeLabel: time, duration: dur}); }
function q(s) { return String.fromCharCode(96) + s + String.fromCharCode(96); }
check("rec-once", rec("allow_once", "Bash(git status)", "10:42 PM", "") === "Allowed once · " + q("Bash(git status)") + " · 10:42 PM");
check("rec-session", rec("allow_session", "Bash(git status)", "10:42 PM", "") === "Allowed for session · " + q("Bash(git status)") + " · 10:42 PM");
check("rec-deny", rec("deny", "Bash(git status)", "", "") === "Denied · " + q("Bash(git status)") + " · by you");
check("rec-expired", rec("expired", "Bash(git status)", "", "5:00") === "Expired · denied after 5:00 · " + q("Bash(git status)"));
check("rec-cancel", rec("cancelled", "Bash(git status)", "", "") === "Cancelled · run stopped by you · " + q("Bash(git status)"));
check("kind-once", ctx.recordKind("allow_once", "ui") === "allow_once" && ctx.recordKind("allow", "ui") === "allow_once");
check("kind-session", ctx.recordKind("allow_session", "ui") === "allow_session");
check("kind-deny", ctx.recordKind("deny", "ui") === "deny");
check("kind-expired", ctx.recordKind("deny", "timeout") === "expired");
check("kind-cancel", ctx.recordKind("deny", "cancel") === "cancelled");
check("dur", ctx.durationLabel(300) === "5:00" && ctx.durationLabel(65) === "1:05");
check("count-60", ctx.countdownAnnounce(61, 60) === "1 minute remaining" && ctx.countdownAnnounce(60, 60) === "");
check("count-10", ctx.countdownAnnounce(11, 10) === "10 seconds remaining" && ctx.countdownAnnounce(10, 10) === "");
check("count-other", ctx.countdownAnnounce(60, 59) === "" && ctx.countdownAnnounce(10, 9) === "" && ctx.countdownAnnounce(31, 30) === "" && ctx.countdownAnnounce(null, "60") === "");
check("focus-next", JSON.stringify(ctx.archiveFocusTarget(true, ["a", "b", "c"], "b")) === JSON.stringify({kind: "row", id: "c"}));
check("focus-prev", JSON.stringify(ctx.archiveFocusTarget(true, ["a", "b", "c"], "c")) === JSON.stringify({kind: "row", id: "b"}));
check("focus-only", JSON.stringify(ctx.archiveFocusTarget(true, ["a"], "a")) === JSON.stringify({kind: "heading"}));
check("focus-narrow", JSON.stringify(ctx.archiveFocusTarget(false, ["a", "b"], "a")) === JSON.stringify({kind: "heading"}));
check("focus-miss", JSON.stringify(ctx.archiveFocusTarget(true, ["a"], "z")) === JSON.stringify({kind: "heading"}));
check("radio-right", JSON.stringify(ctx.themeRadioKey("ArrowRight", 2, 3)) === JSON.stringify({index: 0, select: true}));
check("radio-left", JSON.stringify(ctx.themeRadioKey("ArrowLeft", 0, 3)) === JSON.stringify({index: 2, select: true}));
check("radio-home", JSON.stringify(ctx.themeRadioKey("Home", 1, 3)) === JSON.stringify({index: 0, select: true}));
check("radio-end", JSON.stringify(ctx.themeRadioKey("End", 0, 3)) === JSON.stringify({index: 2, select: true}));
check("radio-vert", JSON.stringify(ctx.themeRadioKey("ArrowDown", 1, 3)) === JSON.stringify({menu: "ArrowDown"}) && JSON.stringify(ctx.themeRadioKey("ArrowUp", 1, 3)) === JSON.stringify({menu: "ArrowUp"}));
check("radio-other", ctx.themeRadioKey("Enter", 0, 3) === null && ctx.themeRadioKey("ArrowRight", 0, 0) === null);
check("retry-visible", ctx.retryTrigger("visible", true, false) === true);
check("retry-focus", ctx.retryTrigger("focus", true, false) === true);
check("retry-online", ctx.retryTrigger("online", true, false) === true);
check("retry-click", ctx.retryTrigger("click", true, false) === true);
check("retry-ignore", ctx.retryTrigger("hidden", true, false) === false && ctx.retryTrigger("blur", true, false) === false && ctx.retryTrigger("offline", true, false) === false);
check("retry-busy", ctx.retryTrigger("visible", true, true) === false && ctx.retryTrigger("focus", false, false) === false && ctx.retryTrigger("online", true, true) === false);
const stamp = ctx.clockLabel(new Date(2020, 0, 1, 22, 42, 0));
check("clock", stamp === "10:42 PM");
const savedThread = [
  {id: "b1", role: "bot", run_id: "r1", content: "Step one: chop the onions."},
  {id: "b2", role: "bot", run_id: "r2", content: "Step one: chop the onions."}
];
const stoppedPartials = [
  {runId: "r1", botId: "b", content: "Step one: chop the onions. "},
  {runId: "r2", botId: "b", content: "Step one: chop the onions.\n"}
];
check("partial-saved", ctx.partialsToShow(savedThread, stoppedPartials, "b").length === 0);
const withCurrent = stoppedPartials.concat([
  {runId: "r1", botId: "b", content: "Step one: chop the onions. "},
  {runId: "r3", botId: "b", content: "Still cooking "},
  {runId: "r3", botId: "b", content: "Still cooking more "}
]);
const shownPartial = ctx.partialsToShow(savedThread, withCurrent, "b");
check("partial-current", shownPartial.length === 1 && shownPartial[0].runId === "r3" && shownPartial[0].content === "Still cooking more ");
check("partial-other-bot", ctx.partialsToShow(savedThread, [{runId: "r3", botId: "other", content: "Still cooking "}], "b").length === 0);
const trimOnly = ctx.partialsToShow(
  [{role: "bot", content: "Step one: chop the onions."}],
  [{runId: "r9", botId: "b", content: "Step one: chop the onions.\n"}],
  "b"
);
check("partial-trim", trimOnly.length === 0);
const trimOtherRun = ctx.partialsToShow(
  [{role: "bot", run_id: "r8", content: "Step one: chop the onions."}],
  [{runId: "r9", botId: "b", content: "Step one: chop the onions.\n"}],
  "b"
);
check("partial-trim-run", trimOtherRun.length === 1 && trimOtherRun[0].runId === "r9");
function bubbleCounts(messages, partials, botId) {
  const counts = {};
  (messages || []).forEach(function (m) {
    if (!m || m.role !== "bot" || !m.run_id) return;
    counts[m.run_id] = (counts[m.run_id] || 0) + 1;
  });
  ctx.partialsToShow(messages, partials, botId).forEach(function (p) {
    counts[p.runId] = (counts[p.runId] || 0) + 1;
  });
  return counts;
}
const bubbles = bubbleCounts(savedThread, withCurrent, "b");
check("partial-one-bubble", bubbles.r1 === 1 && bubbles.r2 === 1 && bubbles.r3 === 1 && Object.keys(bubbles).length === 3);
function serverPerm(name, args, decision, source, at) {
  return {
    kind: "permission",
    name: name,
    arguments: args,
    result_or_error: JSON.stringify({decision: decision, source: source}),
    created_at: at
  };
}
const dupServer = [
  serverPerm("Bash", {command: "rm -rf /tmp/x"}, "deny", "ui", "2020-01-01T00:00:20Z"),
  serverPerm("Bash", "{\"command\":\"git status\"}", "allow_once", "ui", "2020-01-01T00:00:10Z")
];
const dupCards = [
  {runId: "r1", botId: "b", kind: "allow_once", toolLabel: "Bash(git status)", timeLabel: "10:00 PM", duration: ""},
  {runId: "r1", botId: "b", kind: "deny", toolLabel: "Bash(rm -rf /tmp/x)", timeLabel: "10:01 PM", duration: ""},
  {runId: "r1", botId: "b", kind: "allow_session", toolLabel: "Bash(ls)", timeLabel: "10:02 PM", duration: ""}
];
const merged = ctx.mergeRunRecords(dupServer, dupCards, "r1", "b");
check("merge-dedupe", merged.length === 3 && merged[0].kind === "allow_once" && merged[0].toolLabel === "Bash(git status)" && merged[1].kind === "deny" && merged[1].toolLabel === "Bash(rm -rf /tmp/x)" && merged[2].kind === "allow_session" && merged[2].toolLabel === "Bash(ls)");
check("merge-local-once", merged.filter(function (r) { return r.kind === "allow_session"; }).length === 1);
const kindRows = [
  ["allow_once", "ui", "allow_once", ""],
  ["allow_session", "ui", "allow_session", ""],
  ["deny", "ui", "deny", ""],
  ["deny", "timeout", "expired", "5:00"],
  ["deny", "cancel", "cancelled", ""]
];
kindRows.forEach(function (row, i) {
  const label = "Bash(cmd " + i + ")";
  const srv = [serverPerm("Bash", {command: "cmd " + i}, row[0], row[1], "2020-01-01T00:00:0" + i + "Z")];
  const local = [{runId: "r", botId: "b", kind: row[2], toolLabel: label, timeLabel: "1:00 PM", duration: row[3]}];
  const got = ctx.mergeRunRecords(srv, local, "r", "b");
  check("merge-" + row[2], got.length === 1 && got[0].kind === row[2] && got[0].toolLabel === label && (got[0].duration || "") === row[3]);
});
check("record-key", ctx.runRecordKey("r1", "deny", "Bash(ls)") === "r1|deny|Bash(ls)" && ctx.runRecordKey("r1", "deny", "Bash(ls)") !== ctx.runRecordKey("r2", "deny", "Bash(ls)"));
check("merge-other-run", ctx.mergeRunRecords([], [{runId: "r2", botId: "b", kind: "deny", toolLabel: "Bash(ls)", timeLabel: "", duration: ""}], "r1", "b").length === 0);
const pushGot = ctx.mergeRunRecords(
  [serverPerm("git_push", {repo: "owner/name", branch: "main"}, "allow_once", "ui", "2020-01-01T00:00:01Z")],
  [{runId: "r", botId: "b", kind: "allow_once", toolLabel: "git_push owner/name", timeLabel: "", duration: ""}],
  "r", "b"
);
check("merge-push", pushGot.length === 1 && pushGot[0].toolLabel === "git_push owner/name" && pushGot[0].kind === "allow_once");
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}
