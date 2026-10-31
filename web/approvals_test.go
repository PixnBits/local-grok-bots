package web

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestApprovalsCopy(t *testing.T) {
	src := ClientSource()
	for _, s := range []string{
		`const APPROVE_ARM_MS = 1500`,
		`const APPROVAL_POLL_MS = 2000`,
		`const DENY_BODY = '{"decision":"deny"}'`,
		"Nothing waiting",
		"When a bot needs your OK, it shows up here, sorted by risk.",
		"Reconnect to answer.",
		"Can't reach the daemon. Answers are paused until it's back.",
		"⚠ CRITICAL · WE RECOMMEND DENYING",
		"CRITICAL RISK · PERMISSION NEEDED",
		"Couldn't send your answer. The daemon didn't respond. Try again.",
		"Critical approval waiting",
		"Browsers don't allow notifications on plain http. Critical approvals still show here and in the tab title.",
		"Notifications are blocked. Allow notifications for this page in your browser's site settings. Critical approvals still show here and in the tab title.",
		"Get a notification for critical approvals?",
		"HOW LONG SHOULD THIS LAST?",
		"All bots isn't offered",
		"Can't be a rule",
		"Rule saved · Undo",
		"More approve options",
		"Always allow it?",
		"Approve once?",
		"This can't be undone from here and can't become a rule.",
		"How a request is decided",
		"Can't be converted. Add a pattern rule to replace it, then revoke this.",
		"Built-in",
		"Ships with the daemon. Updated with it.",
		"Your stricter entries",
		"They can only raise a level, never lower it.",
		`aria-live="polite"`,
		`aria-live="assertive"`,
		`id="approvals"`,
		`id="view-rules"`,
		`id="menu-alerts"`,
		`id="open-approval-rules"`,
		"button.appr-btn",
		"width: 380px;",
		"width: 400px;",
		"transition: width 1.5s linear;",
		"allowed_scopes",
		"hashIsApprovals",
		"#approvals",
		`"/rules"`,
		"requestPermission",
		"lgb.notify.snoozeUntil",
		"Turn on notifications",
		"Granted for this task",
		"Not granted for this task",
		"carries on without it",
		"carries on without them",
		"Approved on another device",
		"Allowed by rule",
		"Denied by rule",
		"Allowed by task grant",
		"Expired · ",
		"renderBots();\nstartApprovals();\nrefreshDaemon();",
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	if strings.Contains(src, "Stopped after denial") {
		t.Error("deny must not stop a run")
	}
	blocked := "Notifications are blocked. Allow notifications for this page in your browser's site settings. Critical approvals still show here and in the tab title."
	if strings.Contains(blocked, "Try again") {
		t.Error("blocked notification copy must not offer Try again")
	}
	i := strings.Index(src, "function closeApprovalLayer()")
	j := strings.Index(src, "function syncApprovalsHash()")
	if i < 0 || j < i {
		t.Fatal("closeApprovalLayer missing")
	}
	closeBody := src[i:j]
	if strings.Contains(closeBody, "brokerCall") || strings.Contains(closeBody, "DENY_BODY") || strings.Contains(closeBody, "postDecision") {
		t.Error("Escape closes the queue and must not post a decision")
	}
	k := strings.Index(src, `if (typeof approvalKey === "function"`)
	end := strings.Index(src, "let daemonTimer")
	if k < 0 || end < k {
		t.Fatal("approval key handler missing")
	}
	keys := src[k:end]
	if strings.Contains(keys, "postDecision") || strings.Contains(keys, "brokerCall") || strings.Contains(keys, "DENY_BODY") {
		t.Error("keydown must not approve, deny, or post")
	}
	pure := between(t, src, "// approvals-pure:begin", "// approvals-pure:end")
	if strings.Contains(pure, "document.") || strings.Contains(pure, "fetch(") || strings.Contains(pure, "innerHTML") {
		t.Error("approvals pure helpers must stay free of DOM and network")
	}
}

func TestApprovalTitleIgnoresAdvisory(t *testing.T) {
	src := ClientSource()
	body := jsFunc(t, src, "function approvalTitle(")
	if strings.Contains(body, "advisory") {
		t.Fatalf("title renderer reads advisory: %s", body)
	}
	if !strings.Contains(src, "approvalTitle(item)") {
		t.Fatal("card title does not use approvalTitle")
	}
	if strings.Contains(src, "item.advisory && item.advisory.text") {
		t.Fatal("card title still reads advisory text")
	}
}

func TestApprovalsBannerHidesWhenEmpty(t *testing.T) {
	src := ClientSource()
	if !strings.Contains(src, "#approvals-banner[hidden] { display: none !important; }") {
		t.Fatal("empty banner is visible")
	}
	if !strings.Contains(src, `if (!String(banner.textContent || "").trim()) banner.hidden = true;`) {
		t.Fatal("banner stays visible with no text")
	}
}

func TestNotifyPrepromptStacks(t *testing.T) {
	src := ClientSource()
	if !strings.Contains(src, ".appr-alert { flex-direction: column; align-items: stretch; width: 100%;") {
		t.Fatal("notification card is still a row")
	}
	body := jsFunc(t, src, "function renderAlerts(")
	if !strings.Contains(body, "appr-alert-h") || !strings.Contains(body, "appr-alert-actions") || !strings.Contains(body, "notifyBell()") {
		t.Fatal("pre-prompt is not icon, title, body, then buttons")
	}
	if !strings.Contains(body, "PREPROMPT_TITLE") || !strings.Contains(body, "Turn on notifications") || !strings.Contains(body, "Not now") {
		t.Fatal("pre-prompt copy missing")
	}
}

func TestRulesTitleIsHeading(t *testing.T) {
	src := ClientSource()
	if !strings.Contains(src, `<h2 class="solo-title" id="rules-title" tabindex="-1">Approval rules</h2>`) {
		t.Fatal("rules title is not a plain heading")
	}
	if strings.Contains(src, `<input`) && strings.Contains(src, `id="rules-title"`) {
		if !strings.Contains(src, `<h2 class="solo-title" id="rules-title"`) {
			t.Fatal("rules title is an input")
		}
	}
	if strings.Contains(src, `id="rules-title" type=`) || strings.Contains(src, `<input id="rules-title"`) {
		t.Fatal("rules title is an input")
	}
	if !strings.Contains(src, ":focus:not(:focus-visible) { outline-style: none; }") {
		t.Fatal("programmatic focus draws a box")
	}
}

func TestQueueHeaderCountsAndRules(t *testing.T) {
	src := ClientSource()
	if !strings.Contains(src, `id="approvals-sub"`) || !strings.Contains(src, `id="approvals-rules"`) || !strings.Contains(src, `href="/rules"`) {
		t.Fatal("queue header is missing the subtitle or the Rules link")
	}
	if !strings.Contains(src, ">Rules<") || !strings.Contains(src, "queueSubtitle(") {
		t.Fatal("queue header does not render the count or the Rules link")
	}
}

func TestRiskRowShowsAllBots(t *testing.T) {
	src := ClientSource()
	body := jsFunc(t, src, "function renderRiskRow(")
	if strings.Contains(body, `row.applies_to || ""`) {
		t.Fatal("tool kind is still the applies column")
	}
	if !strings.Contains(body, "All bots") || !strings.Contains(body, `el("div", "rules-src", row.applies_to)`) {
		t.Fatal("risk row does not put the tool under the match")
	}
}

func TestTaskTextFlattensWhitespace(t *testing.T) {
	src := ClientSource()
	if !strings.Contains(src, "flattenTaskText(item.task_text)") {
		t.Fatal("task text is rendered raw")
	}
	body := jsFunc(t, src, "function flattenTaskText(")
	if !strings.Contains(body, `/\s+/g`) {
		t.Fatal("task text does not collapse whitespace")
	}
}

func jsFunc(t *testing.T, src, start string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("missing %s", start)
	}
	rest := src[i:]
	j := strings.Index(rest[len(start):], "\nfunction ")
	if j < 0 {
		t.Fatalf("no function after %s", start)
	}
	return rest[:len(start)+j]
}

func TestApprovalsNoExternalURLs(t *testing.T) {
	src := ClientSource()
	stripped := strings.ReplaceAll(src, "http://www.w3.org/2000/svg", "")
	for _, bad := range []string{"http://", "https://", "//cdn"} {
		if i := strings.Index(strings.ToLower(stripped), bad); i >= 0 {
			lo := i - 40
			if lo < 0 {
				lo = 0
			}
			hi := i + 80
			if hi > len(stripped) {
				hi = len(stripped)
			}
			t.Errorf("external URL %q near %q", bad, stripped[lo:hi])
		}
	}
	tagRe := regexp.MustCompile(`(?i)<(script|link)\b([^>]*)>`)
	attrRe := regexp.MustCompile(`(?i)\b(src|href)\s*=\s*("([^"]*)"|'([^']*)')`)
	for _, m := range tagRe.FindAllStringSubmatch(src, -1) {
		tag := strings.ToLower(m[1])
		am := attrRe.FindStringSubmatch(m[2])
		if am == nil {
			continue
		}
		kind := strings.ToLower(am[1])
		if tag == "script" && kind != "src" {
			continue
		}
		if tag == "link" && kind != "href" {
			continue
		}
		val := am[3]
		if val == "" {
			val = am[4]
		}
		if !approvalSameOrigin(val) {
			t.Errorf("%s %s points off origin: %s", tag, kind, val)
		}
	}
}

func approvalSameOrigin(v string) bool {
	if v == "" {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(lower, "data:") {
		return len(v) <= 128
	}
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "//") {
		return false
	}
	if strings.Contains(lower, ":") {
		return false
	}
	return true
}

func TestApprovalsPureHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	snippet, err := json.Marshal(between(t, ClientSource(), "// approvals-pure:begin", "// approvals-pure:end"))
	if err != nil {
		t.Fatal(err)
	}
	route, err := json.Marshal(between(t, ClientSource(), "// route:begin", "// route:end"))
	if err != nil {
		t.Fatal(err)
	}
	pureJSON, err := json.Marshal(pureChecks)
	if err != nil {
		t.Fatal(err)
	}
	routeChecksJSON, err := json.Marshal(routeChecks)
	if err != nil {
		t.Fatal(err)
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const route = ` + string(route) + `;
const pureChecks = ` + string(pureJSON) + `;
const routeChecks = ` + string(routeChecksJSON) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\nthis.out = (function () {\n" + pureChecks + "\n})();", ctx);
vm.runInContext(route + "\nthis.route = (function () {\n" + routeChecks + "\n})();", ctx);
console.log(JSON.stringify({pure: ctx.out, route: ctx.route}));
`
	out := runNode(t, node, script)
	var result struct {
		Pure  []checkRow `json:"pure"`
		Route []checkRow `json:"route"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	reportChecks(t, "pure", result.Pure)
	reportChecks(t, "route", result.Route)
}

type checkRow struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Got  string `json:"got"`
}

func reportChecks(t *testing.T, kind string, rows []checkRow) {
	t.Helper()
	if len(rows) == 0 {
		t.Fatalf("%s checks produced no rows", kind)
	}
	for _, row := range rows {
		if !row.OK {
			t.Errorf("%s %s: %s", kind, row.Name, row.Got)
		}
	}
}

const pureChecks = `
const out = [];
function check(name, cond, got) {
  out.push({name: name, ok: !!cond, got: got == null ? "" : String(got)});
}
const keys = ["Escape", "a", "A", "Enter", "d", "y", " "];
const extras = [{}, {altKey: true}, {ctrlKey: true}, {metaKey: true}];
let approveEver = false;
keys.forEach(function (key) {
  [true, false].forEach(function (typing) {
    extras.forEach(function (extra) {
      const r = approvalKey(Object.assign({key: key}, extra), typing);
      if (!r || r.approve !== false) approveEver = true;
    });
  });
});
check("never-approves", !approveEver, approveEver);
const esc = approvalKey({key: "Escape"}, true);
check("esc-typing", esc.close === true && esc.open === false && esc.approve === false, JSON.stringify(esc));
const openA = approvalKey({key: "a"}, false);
check("a-opens", openA.open === true && openA.approve === false, JSON.stringify(openA));
const typeA = approvalKey({key: "A"}, true);
check("a-typing", typeA.open === false && typeA.approve === false, JSON.stringify(typeA));
check("arm", APPROVE_ARM_MS === 1500, APPROVE_ARM_MS);
check("poll", APPROVAL_POLL_MS === 2000, APPROVAL_POLL_MS);
check("deny-body", DENY_BODY === '{"decision":"deny"}', DENY_BODY);
const high = ladderSteps({level: "high", allowed_scopes: ["once", "task", "bot"]});
check("high-scopes", high.steps.map(function (s) { return s.scope; }).join(",") === "once,task,bot" && high.lockGlobal === true, JSON.stringify(high));
const crit = ladderSteps({level: "critical", allowed_scopes: ["once"]});
check("crit-once", crit.steps.length === 1 && crit.steps[0].scope === "once" && crit.lockGlobal === false, JSON.stringify(crit));
const lowSteps = ladderSteps({level: "low", allowed_scopes: ["once", "task", "bot", "global"]});
check("low-scopes", lowSteps.steps.map(function (s) { return s.scope; }).join(",") === "once,task,bot,global" && lowSteps.lockGlobal === false, JSON.stringify(lowSteps));
check("commit-once", commitLabel("once", "Ada") === "Approve once", commitLabel("once", "Ada"));
check("commit-task", commitLabel("task", "Ada") === "Approve for this task", commitLabel("task", "Ada"));
check("commit-bot", commitLabel("bot", "Ada") === "Approve · always for Ada", commitLabel("bot", "Ada"));
check("commit-all", commitLabel("global", "Ada") === "Approve · always for all bots", commitLabel("global", "Ada"));
const wrap = patternErrorCopy("wrapper", "sh", ["sh", "env", "sudo", "xargs", "python", "node", "npx"]);
check("wrapper", wrap.indexOf("can't start a pattern") >= 0 && wrap.indexOf("sh") >= 0 && wrap.indexOf("npx") < 0, wrap);
check("trail", patternErrorCopy("trailing_wildcard", "", []).indexOf("match the rest") >= 0, patternErrorCopy("trailing_wildcard", "", []));
check("flag", patternErrorCopy("flag_star", "", []).indexOf("Write the flag") >= 0, patternErrorCopy("flag_star", "", []));
check("star-word", patternErrorCopy("star_in_word", "", []).indexOf("whole word") >= 0, patternErrorCopy("star_in_word", "", []));
check("star-first", patternErrorCopy("star_first", "", []).indexOf("command name") >= 0, patternErrorCopy("star_first", "", []));
check("ops", patternErrorCopy("operators", "", []).indexOf("several parts always ask") >= 0, patternErrorCopy("operators", "", []));
check("deny-toast", denyToast("Ada") === "Denied. Ada carries on without it.", denyToast("Ada"));
check("deny-all", denyAllToast(3, "Ada") === "Denied 3 requests. Ada carries on without them.", denyAllToast(3, "Ada"));
check("deny-rec", denyRecord("Ada", "ls /") === "Denied · Ada carries on without it · ls /", denyRecord("Ada", "ls /"));
check("deny-all-rec", denyAllRecord(2, "Ada", "ls") === "Denied 2 · Ada carried on · ls", denyAllRecord(2, "Ada", "ls"));
check("granted", partStatus({granted_for_task: true}, "Ada") === "Granted for this task", partStatus({granted_for_task: true}, "Ada"));
check("not-granted", partStatus({}, "Ada") === "Not granted for this task", partStatus({}, "Ada"));
check("has-rule", partStatus({has_bot_rule: true}, "Ada") === "Has a Ada rule, but no task grant", partStatus({has_bot_rule: true}, "Ada"));
check("expired", recentLabel("expired", "Ada") === "Expired · Ada stopped", recentLabel("expired", "Ada"));
check("elsewhere", showRecent({kind: "approved", bot_id: "a"}, false) === "Approved on another device", showRecent({kind: "approved", bot_id: "a"}, false));
check("own-approve", showRecent({kind: "approved"}, true) === "", showRecent({kind: "approved"}, true));
check("skip-deny", showRecent({kind: "denied"}, false) === "", "denied");
check("by-rule", recentLabel("allowed_by_rule", "A") === "Allowed by rule", recentLabel("allowed_by_rule", "A"));
check("deny-rule", recentLabel("denied_by_rule", "A") === "Denied by rule", recentLabel("denied_by_rule", "A"));
check("by-grant", recentLabel("allowed_by_task_grant", "A") === "Allowed by task grant", recentLabel("allowed_by_task_grant", "A"));
check("title0", criticalTitle("Local Grok Bots", 0) === "Local Grok Bots", criticalTitle("Local Grok Bots", 0));
check("title2", criticalTitle("Ada — Local Grok Bots", 2) === "(2) Critical approval · Ada — Local Grok Bots", criticalTitle("Ada — Local Grok Bots", 2));
check("notify-body", notifyBody("Ada", "rm -rf /tmp") === "Ada wants to rm -rf /tmp. Open Local Grok Bots to decide.", notifyBody("Ada", "rm -rf /tmp"));
check("notify-http", notifyStateLabel(false, "granted", false) === "Not available", notifyStateLabel(false, "granted", false));
check("notify-blocked", notifyStateLabel(true, "denied", false) === "Blocked", notifyStateLabel(true, "denied", false));
check("notify-on", notifyStateLabel(true, "granted", false) === "On", notifyStateLabel(true, "granted", false));
check("notify-off", notifyStateLabel(true, "granted", true) === "Off", notifyStateLabel(true, "granted", true));
check("ident", identicalKey({level: "low", bot_id: "b", argv: ["ls"]}) === "b\n" + JSON.stringify(["ls"]), identicalKey({level: "low", bot_id: "b", argv: ["ls"]}));
check("ident-high", identicalKey({level: "high", bot_id: "b", argv: ["ls"]}) === "", "high");
check("ident-compound", identicalKey({level: "low", compound: true, bot_id: "b", argv: ["ls"]}) === "", "compound");
const items = [
  {id: "a", level: "low", created_at: "2020-01-01T00:00:00Z"},
  {id: "b", level: "critical", created_at: "2020-01-02T00:00:00Z"},
  {id: "c", level: "high", created_at: "2020-01-01T00:00:00Z"}
];
check("order", JSON.stringify(orderApprovalIds(items, [], "")) === JSON.stringify(["b", "c", "a"]), JSON.stringify(orderApprovalIds(items, [], "")));
const pinned = orderApprovalIds(items, ["a", "b", "c"], "a");
check("focus-pin", pinned[0] === "a", JSON.stringify(pinned));
check("hash", hashIsApprovals("#approvals") === true && hashIsApprovals("approvals") === true && hashIsApprovals("#log") === false, "hash");
const rules = [
  {id: "old", effect: "allow", kind: "exact", scope: "bot", bot_id: "b", argv: ["ls"], created_at: "2020-01-01"},
  {id: "new", effect: "allow", kind: "exact", scope: "bot", bot_id: "b", argv: ["ls"], created_at: "2020-02-01"},
  {id: "pat", effect: "allow", kind: "pattern", scope: "bot", bot_id: "b", argv: ["ls"], created_at: "2021-01-01"},
  {id: "deny", effect: "deny", kind: "exact", scope: "bot", bot_id: "b", argv: ["ls"], created_at: "2022-01-01"}
];
const match = matchAllowRule(rules, {argv: ["ls"], bot_id: "b"}, "bot");
check("match-newest", match && match.id === "new", match && match.id);
const start = Date.parse("2020-01-01T00:00:00Z");
check("age-6m", approvalAge(new Date(start), start + 6 * 60000, 0) === "6m", approvalAge(new Date(start), start + 6 * 60000, 0));
check("age-3h", approvalAge(new Date(start), start + (3 * 60 + 12) * 60000, 0) === "3h 12m", approvalAge(new Date(start), start + (3 * 60 + 12) * 60000, 0));
check("age-frozen", approvalAge(new Date(start), start + 100 * 60000, start + 6 * 60000) === "6m", approvalAge(new Date(start), start + 100 * 60000, start + 6 * 60000));
const sinceDate = new Date(2026, 9, 27, 21, 2, 0);
const sinceDays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const sinceWant = "since " + sinceDays[sinceDate.getDay()] + " 9:02 PM";
check("since", approvalSince(sinceDate) === sinceWant, approvalSince(sinceDate) + " vs " + sinceWant);
check("arm-no", armReady({armedAt: 1000}, 2499) === false, armReady({armedAt: 1000}, 2499));
check("arm-yes", armReady({armedAt: 1000}, 2500) === true, armReady({armedAt: 1000}, 2500));
check("arm-unset", armReady({armedAt: 0}, 5000) === false, armReady({armedAt: 0}, 5000));
const critAct = approvalActions({level: "critical", allowed_scopes: ["once"]});
check("crit-act", critAct.deny === "fill" && critAct.approve === "confirm" && critAct.chevron === false, JSON.stringify(critAct));
const highAct = approvalActions({level: "high", allowed_scopes: ["once", "bot"]});
check("high-act", highAct.deny === "outline" && highAct.lockGlobal === true && highAct.chevron === true, JSON.stringify(highAct));
const lowAct = approvalActions({level: "low", allowed_scopes: ["once", "task", "bot", "global"]});
check("low-act", lowAct.batch === true && lowAct.approve === "split-primary", JSON.stringify(lowAct));
const comp = approvalActions({level: "low", compound: true, allowed_scopes: ["once"]});
check("compound", comp.approve === "once" && comp.chevron === false && comp.note === "Can't be a rule", JSON.stringify(comp));
const unc = approvalActions({level: "unclassified", allowed_scopes: ["once", "bot"]});
check("unclassified-lock", unc.lockGlobal === true && unc.approve === "split-primary", JSON.stringify(unc));
check("adv-off", advisorySource({checked: false, source: "table"}) === "Not checked", advisorySource({checked: false, source: "table"}));
check("adv-table", advisorySource({checked: true, source: "table"}, "low") === "Low from the built-in table. Local model: no change.", advisorySource({checked: true, source: "table"}, "low"));
check("adv-crit-table", advisorySource({checked: true, source: "table"}, "critical") === "Critical from the built-in table. Local model: no change.", advisorySource({checked: true, source: "table"}, "critical"));
check("adv-model", advisorySource({checked: true, source: "local model raised this to high"}, "high") === "Local model raised this to high", advisorySource({checked: true, source: "local model raised this to high"}, "high"));
const titled = {level: "critical", tool: "shell", critical_reason: "Reads outside the workspace: /", advisory: {text: "Looks routine; safe to allow."}};
check("title-reason", approvalTitle(titled) === "Reads outside the workspace: /", approvalTitle(titled));
check("title-shell", approvalTitle({level: "low", tool: "shell", advisory: {text: "Looks routine; safe to allow."}}) === "Run a shell command", approvalTitle({level: "low", tool: "shell", advisory: {text: "Looks routine; safe to allow."}}));
check("title-parts", approvalTitle({level: "medium", tool: "shell", compound: true}) === "Run a command with several parts", approvalTitle({level: "medium", tool: "shell", compound: true}));
check("title-edit", approvalTitle({level: "medium", tool: "edit"}) === "Edit a file", approvalTitle({level: "medium", tool: "edit"}));
check("title-no-advisory", approvalTitle.toString().indexOf("advisory") < 0, approvalTitle.toString());
check("task-flat", flattenTaskText("a.txt\nMake exactly") === "a.txt Make exactly", flattenTaskText("a.txt\nMake exactly"));
check("task-spaces", flattenTaskText("  a \n\n b\t") === "a b", flattenTaskText("  a \n\n b\t"));
check("sub-0", queueSubtitle(0, 0) === "0 requests · 0 bots", queueSubtitle(0, 0));
check("sub-1", queueSubtitle(1, 1) === "1 request · 1 bot", queueSubtitle(1, 1));
check("sub-n", queueSubtitle(2, 3) === "2 requests · 3 bots", queueSubtitle(2, 3));
check("preview", previewSummary({would_allow: 3, would_ask: 1, still_asks_critical: 1}, "Ada") === "3 of Ada's last 50 requests would be allowed · 2 still asks", previewSummary({would_allow: 3, would_ask: 1, still_asks_critical: 1}, "Ada"));
check("outcome", outcomeLabel("still_asks_compound", "") === "Still asks · several parts", outcomeLabel("still_asks_compound", ""));
check("no-match", outcomeLabel("no_match", "flag_in_star").indexOf("never matches a flag") >= 0, outcomeLabel("no_match", "flag_in_star"));
check("has-op", exactHasOp("ls && rm") === true && exactHasOp("echo $(id)") === true && exactHasOp("ls -la") === false, "ops");
check("group", groupTitle(0) === "Critical" && groupTitle(1) === "High" && groupTitle(2) === "Medium & Unclassified" && groupTitle(3) === "Low", "groups");
return out;
`

const routeChecks = `
const out = [];
function check(name, cond, got) {
  out.push({name: name, ok: !!cond, got: got == null ? "" : String(got)});
}
check("rules", JSON.stringify(parseLevel("/rules", "", "", null, "")) === JSON.stringify({view: "rules", bot: null}), JSON.stringify(parseLevel("/rules", "", "", null, "")));
check("rules-bot", JSON.stringify(parseLevel("/rules", "", "", null, "?bot=ada")) === JSON.stringify({view: "rules", bot: "ada"}), JSON.stringify(parseLevel("/rules", "", "", null, "?bot=ada")));
check("hash-not-view", JSON.stringify(parseLevel("/bots/abc", "#approvals", "", null, "")) === JSON.stringify({view: "chat", bot: "abc"}), JSON.stringify(parseLevel("/bots/abc", "#approvals", "", null, "")));
check("url-rules", levelURL("", "rules", "ada", "?bot=nope") === "/rules?bot=ada", levelURL("", "rules", "ada", "?bot=nope"));
check("url-rules-home", levelURL("", "rules", null, "") === "/rules", levelURL("", "rules", null, ""));
check("url-rules-space", levelURL("/hds-ab-1-cd", "rules", "a b", "") === "/hds-ab-1-cd/rules?bot=a%20b", levelURL("/hds-ab-1-cd", "rules", "a b", ""));
check("parent-rules", JSON.stringify(parentLevel({view: "rules", bot: "ada"})) === JSON.stringify({view: "chat", bot: "ada"}), JSON.stringify(parentLevel({view: "rules", bot: "ada"})));
check("parent-rules-home", JSON.stringify(parentLevel({view: "rules", bot: null})) === JSON.stringify({view: "bots", bot: null}), JSON.stringify(parentLevel({view: "rules", bot: null})));
const stamp = historyStamp(null, "/bots/abc", "#approvals", "", "");
check("stamp-hash", stamp && stamp.view === "chat" && stamp.bot === "abc", JSON.stringify(stamp));
check("profile-stays", levelURL("", "profile", "abc", "").indexOf("/profile") < 0 && levelURL("", "profile", "abc", "") === "/bots/abc#profile", levelURL("", "profile", "abc", ""));
return out;
`
