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

func TestPermRulePanel(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := ClientSource()
	i := strings.Index(src, "// perm-rules:begin")
	j := strings.Index(src, "// perm-rules:end")
	if i < 0 || j < i {
		t.Fatal("perm-rules markers missing")
	}
	harness := `
class N {
  constructor(tag){this.tag=tag;this.kids=[];this.dataset={};this.attrs={};this.className="";this._text="";this.listeners={};this.style={};}
  append(...k){this.kids.push(...k)}
  replaceChildren(){this.kids=[]}
  addEventListener(type,fn){(this.listeners[type]||=[]).push(fn)}
  click(){return Promise.all((this.listeners.click||[]).map(fn=>fn()))}
  set textContent(v){this._text=v==null?"":String(v)}
  get textContent(){return this._text}
  set type(v){this.attrs.type=v}
  setAttribute(k,v){this.attrs[k]=v}
}
const el=(tag,cls,text)=>{const n=new N(tag); if(cls) n.className=cls; if(text!=null) n.textContent=text; return n};
function riskBadge(risk, effect) {
  const label = risk || effect || "rule";
  return el("span", "risk " + (risk || effect || ""), label);
}
const rulesBox=new N("div");
const sugBox=new N("div");
const errBox=new N("div");
errBox.textContent="stale";
const permAdd=new N("button");
const permAnalyze=new N("button");
const permPattern=new N("input");
permPattern.value="Read(./src/**)";
const permEffect=new N("select");
permEffect.value="allow";
const $=s=>({
  "#perm-rules":rulesBox,
  "#perm-suggestions":sugBox,
  "#profile-err":errBox,
  "#perm-add":permAdd,
  "#perm-analyze":permAnalyze,
  "#perm-pattern":permPattern,
  "#perm-effect":permEffect
}[s]||null);
const posts=[];
const apiFails={};
const api=async(path,opts)=>{
  posts.push({path, method:(opts&&opts.method)||"GET", body:opts&&opts.body});
  if (apiFails[path]) throw new Error(apiFails[path]);
  if (path.endsWith("/permission-rules") && !(opts&&opts.method)) return {rules:[{id:"r1", effect:"allow", pattern:"Read(./src/**)", risk:"low", reason:"ok"}]};
  if (path.endsWith("/permission-suggestions")) return {suggestions:[
    {id:"s1", status:"pending", pattern:"Bash(pwd)", risk:"low", effect:"allow", summary:"ok", examples:["pwd"]},
    {id:"s2", status:"refused", pattern:"Bash(rm *)", risk:"high", effect:"allow", summary:"refused", examples:[]}
  ]};
  return {};
};
const state={botId:"bot-1"};
` + src[i:j] + `
const walk=(n,acc)=>{acc.push(n); (n.kids||[]).forEach(k=>walk(k,acc)); return acc};
const textOf=c=>walk(c,[]).map(n=>n._text||"").join("\n");
const buttons=c=>walk(c,[]).filter(n=>n.tag==="button");
(async()=>{
  await loadPermPanel();
  const pending=sugBox.kids[0];
  const refused=sugBox.kids[1];
  const pendingBtns=buttons(pending).map(b=>b.textContent);
  const refusedBtns=buttons(refused).map(b=>b.textContent);
  const labels=walk(pending,[]).filter(n=>n.tag==="label").map(n=>n._text);
  const revoke=buttons(rulesBox.kids[0]).find(b=>b.textContent==="Revoke");
  errBox.textContent="stale";
  apiFails["/api/bots/bot-1/permission-rules/r1"]="revoke failed";
  await revoke.click();
  const revokeErr=errBox.textContent;
  delete apiFails["/api/bots/bot-1/permission-rules/r1"];
  errBox.textContent="stale";
  const dismiss=buttons(refused).find(b=>b.textContent==="Dismiss");
  apiFails["/api/bots/bot-1/permission-suggestions/s2/dismiss"]="dismiss failed";
  await dismiss.click();
  const dismissErr=errBox.textContent;
  console.log(JSON.stringify({
    pendingBtns, refusedBtns, labels, revokeErr, dismissErr,
    placeholder: "Read(./src/**)"
  }));
})().catch(e=>{console.error(e&&e.stack||e); process.exit(1);});
`
	dir := t.TempDir()
	path := filepath.Join(dir, "perm-rules.js")
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
	if i := strings.LastIndex(line, "{"); i >= 0 {
		line = line[i:]
	}
	var got struct {
		PendingBtns []string `json:"pendingBtns"`
		RefusedBtns []string `json:"refusedBtns"`
		Labels      []string `json:"labels"`
		RevokeErr   string   `json:"revokeErr"`
		DismissErr  string   `json:"dismissErr"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	if strings.Join(got.PendingBtns, ",") != "Accept,Dismiss" {
		t.Fatalf("pending buttons %v", got.PendingBtns)
	}
	if strings.Join(got.RefusedBtns, ",") != "Dismiss" {
		t.Fatalf("refused showed Accept: %v", got.RefusedBtns)
	}
	if len(got.Labels) == 0 || got.Labels[0] != "Pattern" {
		t.Fatalf("pattern label %v", got.Labels)
	}
	if got.RevokeErr != "revoke failed" {
		t.Fatalf("revoke error %q", got.RevokeErr)
	}
	if got.DismissErr != "dismiss failed" {
		t.Fatalf("dismiss error %q", got.DismissErr)
	}
}
