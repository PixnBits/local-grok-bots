package web

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The page's markdown renderer runs under node when node is installed.
// It checks that HTML in a message stays text and unsafe links stay inert.
func TestMarkdownRenderer(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	i := strings.Index(src, "// md:begin")
	j := strings.Index(src, "// md:end")
	if i < 0 || j < i {
		t.Fatal("markdown markers missing from index.html")
	}
	harness := `
class N { constructor(t){this.tag=t;this.kids=[];this.dataset={};this.attrs={}}
  append(...k){this.kids.push(...k)} replaceChildren(){this.kids=[]}
  get children(){return this.kids.filter(k=>k.tag)}
  set textContent(v){this.kids=[{text:v}]} set href(v){this.attrs.href=v}
  set target(v){} set rel(v){} set className(v){} set start(v){} }
const document={createElement:t=>new N(t),createTextNode:t=>({text:t})};
const el=(tag,cls,text)=>{const n=new N(tag); if(text!=null) n.textContent=text; return n};
` + src[i:j] + `
const esc=s=>s.replace(/&/g,"&amp;").replace(/</g,"&lt;");
const h=n=>n.tag?"<"+n.tag+(n.attrs.href?" href=\""+n.attrs.href+"\"":"")+">"+n.kids.map(h).join("")+"</"+n.tag+">":esc(n.text);
const cases=JSON.parse(require("fs").readFileSync(0,"utf8"));
console.log(JSON.stringify(cases.map(c=>h(renderMarkdown(c,new N("div"))))));
`
	dir := t.TempDir()
	path := filepath.Join(dir, "md.js")
	if err := os.WriteFile(path, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ in, want string }{
		{"# Hi\n**b** *i* `c`", "<div><h3>Hi</h3><p><strong>b</strong> <em>i</em> <code>c</code></p></div>"},
		{"<img src=x onerror=alert(1)>", "<div><p>&lt;img src=x onerror=alert(1)></p></div>"},
		{"- a\n- b\n\n1. x", "<div><ul><li>a</li><li>b</li></ul><ol><li>x</li></ol></div>"},
		{"```\n<b>\n```", "<div><pre><code>&lt;b></code></pre></div>"},
		{"[x](javascript:alert(1)) [y](https://e.com)", "<div><p>[x](javascript:alert(1)) <a href=\"https://e.com\">y</a></p></div>"},
		{"snake_case_name", "<div><p>snake_case_name</p></div>"},
		// Lines no block rule takes must not stall the renderer.
		{"```bash title\nx", "<div><p>```bash title<br></br>x</p></div>"},
		{"   - deep", "<div><p>   - deep</p></div>"},
		{"a\n```", "<div><p>a</p><pre><code></code></pre></div>"},
	}
	inputs := make([]string, len(cases))
	for k, c := range cases {
		inputs[k] = c.in
	}
	raw, _ := json.Marshal(inputs)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, path)
	cmd.Stdin = bytes.NewReader(raw)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	for k, c := range cases {
		if got[k] != c.want {
			t.Errorf("%q:\n got  %s\n want %s", c.in, got[k], c.want)
		}
	}
}
