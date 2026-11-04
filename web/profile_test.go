package web

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Profile chips, dirty fields, and Phoenix routine times. Node runs the pure
// helpers between the profile-logic markers. Static pins lock the draft copy.

func TestProfileStatic(t *testing.T) {
	src := ClientSource()
	for _, s := range []string{
		`>Draft</span>`,
		`Not created yet`,
		`New bot · nothing is created until you press Create`,
		`Not created until you press Create`,
		`Create bot`,
		`Discard unsaved changes?`,
		`Routine changes save immediately`,
		`showStatusToast("Saved")`,
		`placeholder="Daemon default"`,
		`Leave blank to use the daemon default.`,
		`Ask and deny rules only narrow what a managed allow would permit.`,
		`box-shadow: 0 0 0 3px var(--accent-soft)`,
		`"chip changed-chip"`,
		`Changed since last save`,
		`aria-label="Log"`,
		`function bindProfileSpy`,
		`An empty GitHub list allows no repositories. It does not inherit the policy list. It can only narrow the policy ceiling.`,
		`// profile-logic:begin`,
		`// profile-logic:end`,
		`function focusProfileHeading`,
		`announce("Saved")`,
		`rescueFocus(() => $("#routine-new").focus())`,
		`removeChipAt(kind, i); input.focus();`,
		`.chips { gap: 16px 8px; }`,
		`rescueFocus(() => $("#save-go").focus());`,
		`state.saveErrorChip && !badChipMessage()`,
		`id="sec-limits"`,
		`id="profile-run-timeout"`,
		`id="profile-tool-rounds"`,
		`id="profile-shell-timeout"`,
		`id="help-run-timeout"`,
		`id="help-tool-rounds"`,
		`id="help-shell-timeout"`,
		`id="err-run-timeout"`,
		`id="err-shell-timeout"`,
		`id="err-tool-rounds"`,
		`id="limit-announce"`,
		`aria-live="polite"`,
		`if (access && access.hidden) setProfilePane("access");`,
		`$("#limit-announce")`,
		`aria-describedby="help-run-timeout err-run-timeout"`,
		`aria-describedby="help-tool-rounds err-tool-rounds"`,
		`aria-describedby="help-shell-timeout err-shell-timeout"`,
		`<label for="profile-run-timeout">Run timeout</label>`,
		`<label for="profile-tool-rounds">Tool rounds</label>`,
		`<label for="profile-shell-timeout">Shell timeout</label>`,
		`function limitHelpText`,
		`Whole seconds only when you change it.`,
		`input::placeholder, textarea::placeholder { color: var(--muted); opacity: 1; }`,
		`Using `,
		`["profile-name", "profile-label", "profile-model"].forEach`,
		`.toggle::before { content: ""; position: absolute; inset: -10px -2px; }`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	for _, s := range []string{
		`last = last.replace(/ MST$/, "");`,
		`.fld.is-dirty, .sec.is-dirty`,
		`box-shadow: inset 3px 0 0 var(--accent)`,
		`padding-left: 8px`,
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has %q", s)
		}
	}
	page := string(IndexHTML)
	for _, id := range []string{
		"fld-mark", "fld-name", "fld-label", "fld-description", "fld-model",
		"fld-grants", "fld-net", "fld-ssh", "fld-github", "fld-tools",
		"fld-run-timeout", "fld-tool-rounds", "fld-shell-timeout",
	} {
		if !fieldHasChangedNote(page, id) {
			t.Errorf("missing Changed note for %s", id)
		}
	}
	assertNoStripe(t, string(AppCSS))
	assertNoStripe(t, page)
}

func fieldHasChangedNote(page, id string) bool {
	key := `id="` + id + `"`
	i := strings.Index(page, key)
	if i < 0 {
		return false
	}
	rest := page[i+len(key):]
	next := len(rest)
	for _, marker := range []string{`id="fld-`, `id="sec-`} {
		if j := strings.Index(rest, marker); j >= 0 && j < next {
			next = j
		}
	}
	start := i
	if start > 60 {
		start = i - 60
	}
	block := page[start : i+len(key)+next]
	if strings.Contains(block, `<p class="help changed" hidden>Changed</p>`) {
		return true
	}
	return strings.Contains(block, `<p class="help changed" id="`+id+`" hidden>Changed</p>`)
}

func assertNoStripe(t *testing.T, src string) {
	t.Helper()
	for _, part := range strings.Split(src, "}") {
		lower := strings.ToLower(part)
		if n := leftBorderWidth(lower); n > 1 {
			t.Errorf("border-left wider than 1px (%d) in %q", n, trimRule(part))
		}
		if n, color := insetLeftStripe(lower); n > 1 && stateColor(color) {
			t.Errorf("inset stripe %dpx %s in %q", n, color, trimRule(part))
		}
	}
}

func leftBorderWidth(rule string) int {
	const key = "border-left:"
	i := strings.Index(rule, key)
	if i < 0 {
		return 0
	}
	rest := strings.TrimSpace(rule[i+len(key):])
	n := 0
	seen := false
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		seen = true
		n = n*10 + int(c-'0')
	}
	if !seen {
		return 0
	}
	return n
}

func insetLeftStripe(rule string) (int, string) {
	const key = "box-shadow:"
	i := strings.Index(rule, key)
	if i < 0 {
		return 0, ""
	}
	rest := rule[i+len(key):]
	j := strings.Index(rest, "inset")
	if j < 0 {
		return 0, ""
	}
	rest = strings.TrimSpace(rest[j+len("inset"):])
	n := 0
	seen := false
	k := 0
	for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
		seen = true
		n = n*10 + int(rest[k]-'0')
		k++
	}
	if !seen || !strings.HasPrefix(rest[k:], "px") {
		return 0, ""
	}
	after := strings.TrimSpace(rest[k+2:])
	if !strings.HasPrefix(after, "0") {
		return 0, ""
	}
	return n, rest
}

func stateColor(fragment string) bool {
	for _, name := range []string{"--accent", "--danger", "--warning", "--success", "--attention"} {
		if strings.Contains(fragment, name) {
			return true
		}
	}
	return false
}

func trimRule(part string) string {
	part = strings.TrimSpace(part)
	if len(part) > 180 {
		return part[:180]
	}
	return part
}

func TestProfileLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	snippet, err := json.Marshal(between(t, ClientSource(), "// profile-logic:begin", "// profile-logic:end"))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{
		"splitChipTokens", "hostEntryValid", "repoEntryValid", "chipInvalidMessage",
		"dirtyFieldLabels", "limitLabel", "aboveCeilingMessage", "toolRoundsRangeMessage", "durationPlaceholder", "limitPlaceholder", "storedAbove", "durationHasFraction", "limitHelpText", "changedLimitPayload", "limitPrecheckError", "firstChangedLimitError", "limitFieldForMessage", "parseGoDurationMs", "scheduleFromBuilder", "scheduleLabel", "builderFromSchedule",
		"routineWhen", "routineRelative", "routineMeta", "routinePreview",
	}
	assign := ""
	for _, n := range names {
		assign += "this." + n + "=" + n + ";\n"
	}
	script := `const vm = require("vm");
const snippet = ` + string(snippet) + `;
const ctx = {};
vm.createContext(ctx);
vm.runInContext(snippet + "\n" + ` + jsonString(assign) + `, ctx);
const cases = [];
function check(name, got, want) {
  cases.push({name: name, ok: got === want, got: got, want: want});
}
check("split-comma", JSON.stringify(ctx.splitChipTokens("docs.example.org, 10.0.0.1")), JSON.stringify(["docs.example.org", "10.0.0.1"]));
check("split-paste", JSON.stringify(ctx.splitChipTokens("a, b\nssh.example.org\t10.1.1.1")), JSON.stringify(["a", "b", "ssh.example.org", "10.1.1.1"]));
check("split-empty", JSON.stringify(ctx.splitChipTokens(" , , ")), "[]");
check("host-name", ctx.hostEntryValid("docs.example.org"), true);
check("host-case", ctx.hostEntryValid("Docs.Example.ORG"), true);
check("host-wild", ctx.hostEntryValid("*.docs.example.org"), true);
check("host-port", ctx.hostEntryValid("docs.example.org:443"), true);
check("host-v4", ctx.hostEntryValid("192.168.0.1"), true);
check("host-v4-port", ctx.hostEntryValid("192.168.0.1:22"), true);
check("host-v6", ctx.hostEntryValid("[2001:db8::1]"), true);
check("host-v6-port", ctx.hostEntryValid("[2001:db8::1]:443"), true);
check("host-feeds", ctx.hostEntryValid("feeds.example"), false);
check("host-bare", ctx.hostEntryValid("example"), false);
check("host-local", ctx.hostEntryValid("localhost"), false);
check("host-port-bad", ctx.hostEntryValid("docs.example.org:0"), false);
check("host-double-wild", ctx.hostEntryValid("*.*.example.com"), false);
check("host-space", ctx.hostEntryValid("not a host"), false);
check("repo-ok", ctx.repoEntryValid("example-org/notes-site"), true);
check("repo-case", ctx.repoEntryValid("Example-Org/Notes-Site"), true);
check("repo-x", ctx.repoEntryValid("x"), false);
check("repo-git", ctx.repoEntryValid("example-org/notes-site.git"), false);
check("repo-extra", ctx.repoEntryValid("example-org/notes-site/extra"), false);
check("msg-host", ctx.chipInvalidMessage("host", "feeds.example"), '"feeds.example" is not a host name. Use a name like docs.example.org.');
check("msg-repo", ctx.chipInvalidMessage("github", "x"), '"x" is not owner/repo. Use a name like example-org/notes-site.');
const base = {
  name: "Ada", label: "", description: "", model: "",
  mark: {shape: "circle", color: "#4C77DD"},
  grants: ["net"], net: ["docs.example.org"], ssh: [], github: [], server_tools: null,
  run_timeout: "", tool_rounds: "", shell_timeout: ""
};
function cur(over) {
  const o = JSON.parse(JSON.stringify(base));
  Object.keys(over || {}).forEach(function (k) { o[k] = over[k]; });
  return o;
}
check("dirty-clean", JSON.stringify(ctx.dirtyFieldLabels(base, cur())), "[]");
check("dirty-label", JSON.stringify(ctx.dirtyFieldLabels(base, cur({label: "Notes"}))), JSON.stringify(["Label"]));
check("dirty-many", JSON.stringify(ctx.dirtyFieldLabels(base, cur({
  label: "Notes", description: "hi", mark: {shape: "square", color: "#4c77dd"},
  grants: ["net", "git"], net: ["docs.example.org", "10.0.0.1"], server_tools: ["web_search"]
}))), JSON.stringify(["Label", "Description", "Mark", "Grants", "Network allowlist", "Server tools"]));
check("dirty-color-case", JSON.stringify(ctx.dirtyFieldLabels(base, cur({mark: {shape: "circle", color: "#4c77dd"}}))), "[]");
check("dirty-tools-order", JSON.stringify(ctx.dirtyFieldLabels(
  cur({server_tools: ["x_search", "web_search"]}),
  cur({server_tools: ["web_search", "x_search"]})
)), "[]");
check("dirty-tools-null", JSON.stringify(ctx.dirtyFieldLabels(base, cur({server_tools: []}))), JSON.stringify(["Server tools"]));
check("dirty-run-timeout", JSON.stringify(ctx.dirtyFieldLabels(base, cur({run_timeout: "5m"}))), JSON.stringify(["Run timeout"]));
check("help-default", ctx.limitHelpText("10m", "policy", "10m", "the built-in default"), "Using 10m, the built-in default.");
check("help-policy", ctx.limitHelpText("3", "policy", "3", "policy.toml"), "Using 3, from policy.toml.");
check("help-admin", ctx.limitHelpText("20s", "policy", "20s", "your administrator"), "Using 20s, the most your administrator allows.");
check("help-bot", ctx.limitHelpText("5m", "bot", "10m", "policy.toml"), "Using 5m, set on this bot. Up to 10m allowed.");
check("help-system", ctx.limitHelpText("30s", "policy", "30s", "this system"), "Using 30s on this system.");
check("help-clamp", ctx.limitHelpText("2m", "policy", "2m", "policy.toml", "5m"), "Using 2m, from policy.toml. This bot asks for 5m, but only 2m is allowed now, so 2m is used.");
check("help-clamp-rounds", ctx.limitHelpText(3, "policy", 3, "policy.toml", "5"), "Using 3, from policy.toml. This bot asks for 5, but only 3 is allowed now, so 3 is used.");
check("help-no-clamp", ctx.limitHelpText("5m", "bot", "10m", "policy.toml", "5m"), "Using 5m, set on this bot. Up to 10m allowed.");
check("help-fraction-legacy", ctx.limitHelpText("1.5s", "bot", "10m", "policy.toml", "1.5s"), "Using 1.5s, set on this bot. Up to 10m allowed. Whole seconds only when you change it.");
check("help-fraction-shell", ctx.limitHelpText("1.5s", "bot", "30s", "the built-in default", "1.5s"), "Using 1.5s, set on this bot. Up to 30s allowed. Whole seconds only when you change it.");
check("help-whole-no-fraction", ctx.limitHelpText("2s", "bot", "30s", "the built-in default", "2s").indexOf("Whole seconds") < 0, true);
const limits = {
  run_timeout: { value: "10m", source: "policy", ceiling: "10m", ceiling_source: "the built-in default" },
  shell_timeout: { value: "30s", source: "policy", ceiling: "10s", ceiling_source: "policy.toml" },
  tool_rounds: { value: 8, source: "policy", ceiling: 8, ceiling_source: "the built-in default" }
};
const stored = { run_timeout: "20s", shell_timeout: "20s", tool_rounds: "6" };
check("payload-unchanged", JSON.stringify(ctx.changedLimitPayload(stored, stored)), "{}");
check("payload-shell", JSON.stringify(ctx.changedLimitPayload(stored, { run_timeout: "20s", shell_timeout: "15s", tool_rounds: "6" })), JSON.stringify({ shell_timeout: "15s" }));
check("payload-clear-rounds", JSON.stringify(ctx.changedLimitPayload(stored, { run_timeout: "20s", shell_timeout: "20s", tool_rounds: "" })), JSON.stringify({ tool_rounds: 0 }));
check("precheck-skip-unchanged", ctx.firstChangedLimitError(stored, stored, limits, false), null);
check("precheck-changed-shell", ctx.firstChangedLimitError(stored, { run_timeout: "20s", shell_timeout: "15s", tool_rounds: "6" }, limits, false).message, "Shell timeout can be at most 10s (set in policy.toml). Enter 10s or less, or leave it blank to use 10s.");
check("precheck-rounds", ctx.firstChangedLimitError({ tool_rounds: "3" }, { tool_rounds: "9" }, limits, false).message, "Tool rounds can be at most 8. Enter 8 or less, or leave it blank.");
check("precheck-fraction", ctx.limitPrecheckError("run_timeout", "1.5s", limits), "Use whole seconds, like 2s.");
check("precheck-zero", ctx.limitPrecheckError("run_timeout", "0", limits), "Enter a time like 90s, 5m or 1h.");
check("precheck-negative", ctx.limitPrecheckError("shell_timeout", "-1m", limits), "Enter a time like 90s, 5m or 1h.");
check("precheck-same-zero", ctx.limitPrecheckError("run_timeout", "0", limits) === ctx.limitPrecheckError("run_timeout", "-1m", limits), true);
check("precheck-rounds-fraction", ctx.limitPrecheckError("tool_rounds", "2.5", limits), "Enter a whole number from 1 to 8.");
check("precheck-rounds-zero", ctx.limitPrecheckError("tool_rounds", "0", limits), "Enter a whole number from 1 to 8.");
check("precheck-rounds-neg", ctx.limitPrecheckError("tool_rounds", "-1", limits), "Enter a whole number from 1 to 8.");
check("precheck-rounds-huge", ctx.limitPrecheckError("tool_rounds", "101", limits), "Enter a whole number from 1 to 8.");
check("precheck-admin", ctx.limitPrecheckError("shell_timeout", "25s", { shell_timeout: { ceiling: "20s", ceiling_source: "your administrator" } }), "Shell timeout can be at most 20s, the most your administrator allows. Enter 20s or less.");
check("precheck-system", ctx.limitPrecheckError("shell_timeout", "31s", { shell_timeout: { ceiling: "30s", ceiling_source: "this system" } }), "Shell timeout can be at most 30s on this system. Enter 30s or less.");
check("precheck-default-run", ctx.aboveCeilingMessage("run_timeout", "10m", "the built-in default"), "Run timeout can be at most 10m. Enter 10m or less, or leave it blank.");
check("placeholder-blank", ctx.durationPlaceholder("10m"), "10m (e.g. 90s, 5m, 1h)");
check("placeholder-stored", ctx.limitPlaceholder("run_timeout", "5m", "10m"), "e.g. 90s, 5m, 1h");
check("placeholder-rounds", ctx.limitPlaceholder("tool_rounds", "", "8"), "8");
check("field-shell", ctx.limitFieldForMessage("Shell timeout can be at most 10s (set in policy.toml). Enter 10s or less, or leave it blank to use 10s.", limits, { shell_timeout: "15s" }), "shell_timeout");
check("field-whole", ctx.limitFieldForMessage("Use whole seconds, like 2s.", limits, { shell_timeout: "500ms" }), "shell_timeout");
check("field-rounds", ctx.limitFieldForMessage("Enter a whole number from 1 to 8.", limits, { tool_rounds: "2.5" }), "tool_rounds");
check("dur-10m", ctx.parseGoDurationMs("10m"), 600000);
check("dur-1s", ctx.parseGoDurationMs("1s"), 1000);
check("sched-min", ctx.scheduleFromBuilder("every", 30, "minutes"), "every 30m");
check("sched-hour", ctx.scheduleFromBuilder("every", "2", "hours"), "every 2h");
check("sched-day", ctx.scheduleFromBuilder("every", 1, "days"), "every 1d");
check("sched-pad", ctx.scheduleFromBuilder("every", " 3 ", "minutes"), "every 3m");
check("sched-once", ctx.scheduleFromBuilder("once", 1, "days"), "");
check("sched-zero", ctx.scheduleFromBuilder("every", 0, "days"), "");
check("sched-frac", ctx.scheduleFromBuilder("every", 1.5, "hours"), "");
check("label-30m", ctx.scheduleLabel("every 30m"), "every 30 min");
check("label-bare", ctx.scheduleLabel("30m"), "every 30 min");
check("label-once", ctx.scheduleLabel("once"), "once");
check("label-day", ctx.scheduleLabel("every 1d"), "every 1 day");
check("label-hours", ctx.scheduleLabel("2h"), "every 2 hours");
check("label-hour", ctx.scheduleLabel("1h"), "every 1 hour");
check("label-sec", ctx.scheduleLabel("30s"), "every 30 sec");
check("builder-30", JSON.stringify(ctx.builderFromSchedule("every 30m")), JSON.stringify({n: 30, unit: "minutes"}));
check("builder-once", ctx.builderFromSchedule("once"), null);
check("builder-sec", ctx.builderFromSchedule("30s"), null);
const sun = "2026-10-25T14:00:00Z";
const sameDay = Date.parse("2026-10-25T16:00:00Z");
const friday = Date.parse("2026-10-23T16:00:00Z");
const saturday = Date.parse("2026-10-24T16:00:00Z");
check("when-today", ctx.routineWhen(sun, sameDay), "today 7:00 AM MST");
check("when-weekday", ctx.routineWhen(sun, friday), "Sun 7:00 AM MST");
check("when-tomorrow", ctx.routineWhen(sun, saturday), "tomorrow 7:00 AM MST");
check("rel-future", ctx.routineRelative("2026-10-25T16:00:00Z", Date.parse("2026-10-25T07:34:00Z")), "in 8h 26m");
check("rel-past", ctx.routineRelative(sun, sameDay), "2h ago");
check("meta-paused", ctx.routineMeta({enabled: false, name: "Digest"}, sameDay), "Paused · turn on to schedule");
check("meta-line", ctx.routineMeta({
  enabled: true,
  next_fire_at: sun,
  last_fire_at: "2026-10-23T14:00:00Z"
}, friday), "Next: Sun 7:00 AM MST · in 46h · Last: today 7:00 AM MST");
check("preview-day", ctx.routinePreview("every 1d", Date.parse("2026-10-24T14:00:00Z")), "Runs every 1 day, first run Sun Oct 25 7:00 AM MST");
check("preview-min", ctx.routinePreview("every 30m", Date.parse("2026-10-25T13:30:00Z")), "Runs every 30 min, first run Sun Oct 25 7:00 AM MST");
check("when-bad", ctx.routineWhen("not-a-date", sameDay), "");
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func sliceFrom(t *testing.T, src, begin, end string) string {
	t.Helper()
	i := strings.Index(src, begin)
	j := strings.Index(src, end)
	if i < 0 || j <= i {
		t.Fatalf("slice %s .. %s missing", begin, end)
	}
	return src[i:j]
}

// openProfile must apply a bot without throwing. Commit 440a10a dropped
// SERVER_TOOL_NAMES and paintServerTools threw ReferenceError inside openProfile.
func TestProfileOpenAppliesFields(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	src := ClientSource()
	tools := sliceFrom(t, src, "const SERVER_TOOL_NAMES", "async function duplicateBot")
	apply := sliceFrom(t, src, "function applyBotFields", "function blankDraftFields")
	open := sliceFrom(t, src, "async function openProfile", "// scroll:begin")
	script := `class N {
  constructor(tag){this.tag=tag;this.kids=[];this.className="";this.attrs={};this.value="";this.checked=false;this.name="";this.type="";}
  append(...k){this.kids.push(...k)}
  replaceChildren(){this.kids=[]}
  addEventListener(){}
  set textContent(v){this._text=v==null?"":String(v)}
  get textContent(){return this._text||""}
}
const el=(tag,cls,text)=>{const n=new N(tag); if(cls) n.className=cls; if(text!=null) n.textContent=text; return n};
const picks={kids:[], replaceChildren(){this.kids=[]}, append(n){this.kids.push(n)}, classList:{toggle(){}}};
const fields={};
function field(id){return fields[id]||(fields[id]={value:"",style:{},textContent:""})}
function $(s){
  if(s==="#server-tools-picks") return picks;
  if(s==="#profile-name") return field("name");
  if(s==="#profile-label") return field("label");
  if(s==="#profile-description") return field("description");
  if(s==="#profile-model") return field("model");
  if(s==="#profile-err") return field("err");
  return field(s);
}
const document={
  createElement(){return new N("input")},
  createTextNode(t){return {text:String(t)}},
  querySelectorAll(){return []}
};
const COLORS=["#4C77DD"];
let navBypass=false;
const state={view:"bots",draft:false,botId:null,bots:[],profileBase:null,profileLoad:0,saveError:"",mark:{shape:"circle",color:"#4C77DD"}};
function noop(){}
const setGrants=noop, setChipList=noop, setServerMode=noop, paintWarnings=noop, paintMarkPicker=noop, syncProfileHeadingName=noop, syncServerToolsMode=noop, paintDirty=noop;
const fillLimitInputs=noop, paintLimitHelp=noop, clearLimitErrors=noop;
const setProfilePane=noop, profileDirty=()=>false, confirmLeave=noop, closeMenu=noop, closeState=noop, closeRoutineForm=noop;
const readProfile=()=>({name:field("name").value});
const loadRoutines=async()=>{};
const showRoutineErr=noop, loadPermPanel=async()=>{}, showPermErr=noop, commitLevel=noop, setView=noop, setTitle=noop, focusPane=noop, resetScrollTops=noop;
const api=async()=>({
  id:"bot-1", name:"Ada", label:"Notes", description:"Keeps notes", model:"grok-3",
  mark:{shape:"hex", color:"#218C57"}, grants:["net"],
  net_allow:["docs.example.org"], ssh_allow:[], github_allow:["example-org/notes-site"],
  server_tools:["web_search"], warnings:[]
});
` + tools + "\n" + apply + "\n" + open + `
function toolState(){
  const out=[];
  for (const label of picks.kids) {
    let value="", checked=false;
    (function walk(n){
      if(!n) return;
      if(n.tag==="input") { value=n.value; checked=!!n.checked; }
      (n.kids||[]).forEach(walk);
    })(label);
    out.push(value+":"+checked);
  }
  return out;
}
(async()=>{
  await openProfile("bot-1");
  const opened={name:field("name").value, label:field("label").value, model:field("model").value, tools:toolState()};
  applyBotFields({name:"Bea", server_tools:null, mark:{shape:"circle", color:"#4C77DD"}});
  const afterNull=toolState();
  const cases=[
    {name:"open-name", ok:opened.name==="Ada" && opened.label==="Notes"},
    {name:"open-model", ok:opened.model==="grok-3"},
    {name:"open-bot", ok:state.botId==="bot-1" && state.draft===false},
    {name:"tools-order", ok:JSON.stringify(opened.tools)===JSON.stringify(["web_search:true","x_search:false"])},
    {name:"tools-null", ok:JSON.stringify(afterNull)===JSON.stringify(["web_search:false","x_search:false"])},
    {name:"const-pinned", ok:JSON.stringify(SERVER_TOOL_NAMES)===JSON.stringify(["web_search","x_search"])}
  ];
  console.log(JSON.stringify(cases));
})().catch(e=>{console.error(e&&e.stack||String(e)); process.exit(1);});
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func TestRevealLimitFailure(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	fn := sliceFrom(t, ClientSource(), "function setLimitAnnounce", "function setSaving")
	script := `const fn = ` + jsonString(fn) + `;
const access = { hidden: true };
const live = { textContent: "stale failure" };
const order = [];
const field = {
  focused: false,
  scrolled: null,
  focus() { this.focused = true; order.push("focus"); },
  scrollIntoView(opts) { this.scrolled = opts; order.push("scroll"); }
};
function $(sel) {
  if (sel === "#profile-access") return access;
  if (sel === "#limit-announce") return live;
  if (sel === "#profile-shell-timeout") return field;
  return null;
}
let pane = "";
function setProfilePane(name) { pane = name; access.hidden = false; }
eval(fn);
const msg = "Shell timeout can be at most 10s (set in policy.toml). Enter 10s or less, or leave it blank to use 10s.";
revealLimitFailure("profile-shell-timeout", msg);
const cases = [];
function check(name, got, want) { cases.push({name: name, ok: got === want, got: got, want: want}); }
check("opened", pane, "access");
check("visible", access.hidden, false);
check("focused", field.focused, true);
check("announced", live.textContent, msg);
check("replaced", live.textContent.indexOf("stale") < 0, true);
check("order", order.join(","), "focus,scroll");
check("scrolled", JSON.stringify(field.scrolled), JSON.stringify({block:"center"}));
pane = "chat";
field.focused = false;
access.hidden = false;
revealLimitFailure("profile-shell-timeout", "again");
check("stays", pane, "chat");
check("refocus", field.focused, true);
check("again", live.textContent, "again");
console.log(JSON.stringify(cases));
`
	raw := runNode(t, node, script)
	assertCases(t, raw)
}

func TestLimitCopyUI(t *testing.T) {
	page := string(IndexHTML)
	for _, id := range []string{"profile-run-timeout", "profile-tool-rounds", "profile-shell-timeout"} {
		label := `<label for="` + id + `">`
		i := strings.Index(page, label)
		if i < 0 {
			t.Fatalf("missing %s", label)
		}
		chunk := page[i:]
		closeAt := strings.Index(chunk, "</label>")
		if closeAt < 0 || strings.Contains(chunk[:closeAt], "<p") || strings.Contains(chunk[:closeAt], "<input") {
			t.Fatalf("label wraps the input or help for %s", id)
		}
	}
	if strings.Count(page, `placeholder="e.g. 90s, 5m, 1h"`) < 2 {
		t.Fatal("duration hint missing on a timeout field")
	}
	css := string(AppCSS)
	rule := "#sec-limits .fld input { height: 44px; scroll-margin-bottom: 160px; }"
	idx := strings.Index(css, rule)
	if idx < 0 {
		t.Fatal("44px limit input rule missing")
	}
	media := strings.LastIndex(css[:idx], "@media (max-width: 540px)")
	depth := 0
	for i := media; i >= 0 && i < idx; i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	if media < 0 || depth < 1 {
		t.Fatal("44px rule is outside the 540px query")
	}
	if !strings.Contains(css, "#sec-limits .fld { scroll-margin-bottom: 160px; }") {
		t.Fatal("field scroll margin missing")
	}
	js := string(AppJS)
	n := 0
	rest := js
	needle := `setLimitAnnounce("Saved.");`
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			break
		}
		after := strings.TrimLeft(rest[i+len(needle):], "\n\t ")
		if strings.HasPrefix(after, "clearLimitErrors();") {
			n++
		}
		rest = rest[i+len(needle):]
	}
	if n < 2 {
		t.Fatalf("successful save clears the live region %d times", n)
	}
	if !strings.Contains(js, `n.scrollIntoView({ block: "center" })`) {
		t.Fatal("revealLimitFailure does not scroll the field")
	}
	if strings.Contains(js, `msg.indexOf(f.key)`) {
		t.Fatal("save still matches raw field keys")
	}
	if !strings.Contains(js, `input.setAttribute("aria-describedby", f.help + " " + f.err);`) {
		t.Fatal("aria-describedby drops the error id")
	}
}
