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
	src := string(IndexHTML)
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
		`box-shadow: inset 3px 0 0 var(--accent), 0 0 0 3px var(--accent-soft)`,
		`aria-label="Log"`,
		`function bindProfileSpy`,
		`An empty GitHub list allows no repositories. It does not inherit the policy list. It can only narrow the policy ceiling.`,
		`// profile-logic:begin`,
		`// profile-logic:end`,
		`function focusProfileHeading`,
		`announce("Saved")`,
		`rescueFocus(() => $("#routine-new").focus())`,
		`removeChipAt(kind, i); input.focus();`,
		`state.saveErrorChip && !badChipMessage()`,
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
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has %q", s)
		}
	}
}

func TestProfileLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node not installed")
	}
	snippet, err := json.Marshal(between(t, string(IndexHTML), "// profile-logic:begin", "// profile-logic:end"))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{
		"splitChipTokens", "hostEntryValid", "repoEntryValid", "chipInvalidMessage",
		"dirtyFieldLabels", "scheduleFromBuilder", "scheduleLabel", "builderFromSchedule",
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
  grants: ["net"], net: ["docs.example.org"], ssh: [], github: [], server_tools: null
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
	src := string(IndexHTML)
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
