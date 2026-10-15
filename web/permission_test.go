package web

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPermissionHandlersPresent(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		"permission_request",
		"permission_decision",
		"&prompts=1",
		"showPermissionRequest",
		"showPermissionDecision",
		"Allow once",
		"Allow for session",
		"session_allowed",
		"/permissions/",
		"allow_once",
		"allow_session",
		`"Deny"`,
		"Submit",
		"Skip",
		"perm-header",
		"perm-question",
		"ExitPlanMode",
		`kind === "question"`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %s", s)
		}
	}
	i := strings.Index(src, "// perm:begin")
	j := strings.Index(src, "// perm:end")
	if i < 0 || j < i {
		t.Fatal("permission handler markers missing")
	}
	if strings.Contains(src[i:j], "innerHTML") {
		t.Fatal("permission card writes untrusted values with innerHTML")
	}
}

func TestPermissionCard(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	i := strings.Index(src, "// perm:begin")
	j := strings.Index(src, "// perm:end")
	if i < 0 || j < i {
		t.Fatal("permission handler markers missing")
	}
	harness := `
class N {
  constructor(tag){this.tag=tag;this.kids=[];this.dataset={};this.attrs={};this.className="";this.disabled=false;this._text="";this.listeners={};
    this.classList={add:(c)=>{this.className += " "+c;}};}
  append(...k){this.kids.push(...k)}
  querySelectorAll(sel){return sel==="button"?this.kids.filter(k=>k.tag==="button"):[]}
  addEventListener(type,fn){(this.listeners[type]||=[]).push(fn)}
  click(){(this.listeners.click||[]).forEach(fn=>fn())}
  set textContent(v){this._text=v==null?"":String(v)}
  get textContent(){return this._text}
  set type(v){this.attrs.type=v}
  set innerHTML(v){this.kids.push({tag:"html",_text:String(v),kids:[]})}
}
const el=(tag,cls,text)=>{const n=new N(tag); if(cls) n.className=cls; if(text!=null) n.textContent=text; return n};
const live=new N("div");
const $=(s)=>s==="#live"?live:null;
const posts=[];
const api=async(path,opts)=>{posts.push({path, body:opts&&opts.body});};
const state={botId:"bot-1"};
` + src[i:j] + `
const walk=(n,acc)=>{acc.push(n); (n.kids||[]).forEach(k=>walk(k,acc)); return acc};
const cardOf=id=>live.kids.find(c=>c.dataset&&c.dataset.id===id);
const buttons=c=>walk(c,[]).filter(n=>n.tag==="button");
const textOf=c=>walk(c,[]).map(n=>n._text||"").join("\n");
const future=new Date(Date.now()+5000).toISOString();
const past=new Date(Date.now()-10).toISOString();
showPermissionRequest({id:"r1", run_id:"run-1", tool:"<img src=x onerror=alert(1)>", arguments:{command:"<script>alert(1)</script>", api_key:"[redacted]"}, deadline:future, session_allowed:false}, "run-1");
showPermissionRequest({id:"r2", run_id:"run-1", tool:"Bash", arguments:{command:"ls"}, deadline:future, session_allowed:true}, "run-1");
showPermissionRequest({id:"r3", run_id:"run-1", tool:"Read", arguments:{path:"a"}, deadline:past, session_allowed:true}, "run-1");
showPermissionRequest({id:"r4", run_id:"run-9", tool:"Edit", arguments:{}, deadline:future, session_allowed:false}, "run-9");
buttons(cardOf("r4")).find(b=>b.textContent==="Deny").click();
const c1=cardOf("r1");
const b1=buttons(c1);
const labels1=b1.map(b=>b.textContent);
if (labels1.join(",")!=="Allow once,Deny") throw new Error("buttons "+labels1.join(","));
if (walk(c1,[]).some(n=>n.tag==="img"||n.tag==="script"||n.tag==="html")) throw new Error("untrusted value became markup");
if (!textOf(c1).includes("<img src=x onerror=alert(1)>")) throw new Error("tool name dropped");
if (!textOf(c1).includes("<script>alert(1)</script>")) throw new Error("args dropped");
if (!textOf(c1).includes("[redacted]")) throw new Error("redacted arg dropped");
const count=walk(c1,[]).find(n=>n.className==="perm-count");
if (!count || !/^[0-9]+s$/.test(count.textContent)) throw new Error("countdown "+(count&&count.textContent));
const sess=buttons(cardOf("r2")).find(b=>b.textContent==="Allow for session");
if (!sess) throw new Error("session button missing");
b1[0].click();
b1[1].click();
sess.click();
const inputsOf=c=>walk(c,[]).filter(n=>n.tag==="input");
const qSingle={question:"Which library?", header:"Lib", multiSelect:false, options:[{label:"Go", description:"Go toolchain"},{label:"Rust", description:"Rust toolchain"}]};
const qMulti={question:"Which libraries?", header:"Libs", multiSelect:true, options:[{label:"Go", description:"Go toolchain"},{label:"Rust", description:"Rust toolchain"}]};
showPermissionRequest({id:"q1", run_id:"run-1", tool:"AskUserQuestion", kind:"question", deadline:future, session_allowed:true, questions:[qSingle]}, "run-1");
showPermissionRequest({id:"q2", run_id:"run-1", tool:"AskUserQuestion", kind:"question", deadline:future, session_allowed:true, questions:[qMulti]}, "run-1");
showPermissionRequest({id:"q3", run_id:"run-1", tool:"AskUserQuestion", kind:"question", deadline:future, session_allowed:false, questions:[qSingle]}, "run-1");
showPermissionRequest({id:"q5", run_id:"run-1", tool:"AskUserQuestion", kind:"question", deadline:future, session_allowed:false, questions:[{question:"<img src=x>", header:"<b>", multiSelect:false, options:[{label:"<script>", description:"<i>d</i>"},{label:"B", description:"ok"}]}]}, "run-1");
showPermissionRequest({id:"q4", run_id:"run-1", tool:"AskUserQuestion", kind:"question", deadline:future, session_allowed:false, questions:[qSingle]}, "run-1");
showPermissionRequest({id:"p1", run_id:"run-1", tool:"ExitPlanMode", arguments:{plan:"ship the plan", command:"<no>"}, deadline:future, session_allowed:false}, "run-1");
const q1=cardOf("q1");
if (buttons(q1).map(b=>b.textContent).join(",")!=="Submit,Skip") throw new Error("question buttons "+buttons(q1).map(b=>b.textContent).join(","));
if (textOf(q1).includes("Allow once") || textOf(q1).includes("Allow for session")) throw new Error("question card offered allow");
if (!textOf(q1).includes("Lib") || !textOf(q1).includes("Which library?") || !textOf(q1).includes("Go toolchain")) throw new Error("question text "+textOf(q1));
const qCount=walk(q1,[]).find(n=>n.className==="perm-count");
if (!qCount || !/^[0-9]+s$/.test(qCount.textContent)) throw new Error("question countdown");
const q1in=inputsOf(q1);
if (q1in.length!==4 || q1in[0].attrs.type!=="radio" || q1in[2].attrs.type!=="radio" || q1in[3].attrs.type!=="text") throw new Error("single inputs");
buttons(q1).find(b=>b.textContent==="Submit").click();
if (!textOf(q1).includes("Answer each question")) throw new Error("empty submit");
q1in[0].checked=true;
buttons(q1).find(b=>b.textContent==="Submit").click();
const q2in=inputsOf(cardOf("q2"));
if (q2in.length!==3 || q2in[0].attrs.type!=="checkbox" || q2in[2].attrs.type!=="text") throw new Error("multi inputs");
q2in[0].checked=true; q2in[1].checked=true; q2in[2].value="my own";
buttons(cardOf("q2")).find(b=>b.textContent==="Submit").click();
const q3in=inputsOf(cardOf("q3"));
q3in[3].value="my own pick";
(q3in[3].listeners.input||[]).forEach(fn=>fn());
if (!q3in[2].checked || q3in[0].checked) throw new Error("other did not select");
buttons(cardOf("q3")).find(b=>b.textContent==="Submit").click();
buttons(cardOf("q4")).find(b=>b.textContent==="Skip").click();
const q5=cardOf("q5");
if (walk(q5,[]).some(n=>n.tag==="img"||n.tag==="script"||n.tag==="html")) throw new Error("question markup");
if (!textOf(q5).includes("<img src=x>") || !textOf(q5).includes("<script>") || !textOf(q5).includes("<i>d</i>")) throw new Error("question text dropped");
if (!textOf(cardOf("p1")).includes("ship the plan")) throw new Error("plan dropped");
if (buttons(cardOf("p1")).map(b=>b.textContent).join(",")!=="Allow once,Deny") throw new Error("plan buttons");
showPermissionDecision({id:"q1", decision:"answer", source:"ui", tool:"AskUserQuestion", kind:"question"});
setTimeout(()=>{
  let code = 0;
  try {
    showPermissionDecision({id:"r1", decision:"allow_once", source:"ui", tool:"<img src=x onerror=alert(1)>"});
    const out=walk(c1,[]).find(n=>n.className==="perm-outcome");
    const disabled=buttons(c1).every(b=>b.disabled);
    const c3=cardOf("r3");
    const out3=walk(c3,[]).find(n=>n.className==="perm-outcome");
    const result={
      posts,
      outcome: out?out.textContent:"",
      disabled,
      timeout: out3?out3.textContent:"",
      timeoutDisabled: buttons(c3).every(b=>b.disabled),
      questionOutcome: (walk(q1,[]).find(n=>n.className==="perm-outcome")||{}).textContent||"",
      questionDisabled: inputsOf(q1).every(n=>n.disabled) && buttons(q1).every(b=>b.disabled)
    };
    console.log(JSON.stringify(result));
  } catch (e) {
    console.error(e && e.stack || e);
    code = 1;
  } finally {
    clearPermissionCards();
  }
  process.exit(code);
}, 40);
`
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.js")
	if err := os.WriteFile(path, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	line := strings.TrimSpace(string(out))
	if i := strings.Index(line, "\n{"); i >= 0 {
		line = strings.TrimSpace(line[i+1:])
	}
	var got struct {
		Posts []struct {
			Path string `json:"path"`
			Body string `json:"body"`
		} `json:"posts"`
		Outcome          string `json:"outcome"`
		Disabled         bool   `json:"disabled"`
		Timeout          string `json:"timeout"`
		TimeoutDisabled  bool   `json:"timeoutDisabled"`
		QuestionOutcome  string `json:"questionOutcome"`
		QuestionDisabled bool   `json:"questionDisabled"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	if !got.Disabled || got.Outcome != "allow_once (ui)" {
		t.Fatalf("decision card %+v", got)
	}
	if !got.TimeoutDisabled || got.Timeout != "deny (timeout)" {
		t.Fatalf("timeout card %+v", got)
	}
	if got.QuestionOutcome != "answer (ui)" || !got.QuestionDisabled {
		t.Fatalf("question card %+v", got)
	}
	want := map[string]string{
		"/api/bots/bot-1/runs/run-1/permissions/r1": `{"decision":"allow_once"}`,
		"/api/bots/bot-1/runs/run-1/permissions/r2": `{"decision":"allow_session"}`,
		"/api/bots/bot-1/runs/run-9/permissions/r4": `{"decision":"deny"}`,
		"/api/bots/bot-1/runs/run-1/permissions/q1": `{"decision":"answer","answers":{"Which library?":"Go"}}`,
		"/api/bots/bot-1/runs/run-1/permissions/q2": `{"decision":"answer","answers":{"Which libraries?":"Go, Rust, my own"}}`,
		"/api/bots/bot-1/runs/run-1/permissions/q3": `{"decision":"answer","answers":{"Which library?":"my own pick"}}`,
		"/api/bots/bot-1/runs/run-1/permissions/q4": `{"decision":"deny"}`,
	}
	gotPosts := map[string]string{}
	for _, p := range got.Posts {
		gotPosts[p.Path] = p.Body
	}
	for path, body := range want {
		if gotPosts[path] != body {
			t.Fatalf("post %s = %q, posts %+v", path, gotPosts[path], got.Posts)
		}
	}
}
