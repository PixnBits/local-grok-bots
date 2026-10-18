package web

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPermissionLine runs the page's permission-record formatter under node.
func TestPermissionLine(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	i := strings.Index(src, "// permline:begin")
	j := strings.Index(src, "// permline:end")
	if i < 0 || j < i {
		t.Fatal("permline markers missing")
	}
	if strings.Contains(src[i:j], "innerHTML") {
		t.Fatal("permission line uses innerHTML")
	}
	script := src[i:j] + `
const out = [
  permissionLine({kind:"permission", name:"Bash", ok:true, arguments:{command:"git status"}, result_or_error:'{"decision":"allow","source":"ui"}'}),
  permissionLine({kind:"permission", name:"Bash", ok:false, arguments:{command:"rm -rf build"}, result_or_error:'{"decision":"deny","source":"policy","rule":"Bash(rm *)"}'}),
  permissionLine({kind:"permission", name:"Edit", ok:false, arguments:{}, result_or_error:"not json"}),
  permissionLine({kind:"permission", name:"Bash", ok:true, arguments:{command:"ls"}, result_or_error:'{"decision":"allow_once","allowed":true,"source":"ui"}'}),
  permissionLine({kind:"permission", name:"Bash", ok:false, arguments:{command:"ls"}, result_or_error:'{"decision":"allow_session","source":"ui"}'}),
  String(hasToolRecords([{kind:"text"},{kind:"permission"}])),
  String(hasToolRecords([{kind:"text"}])),
  toolVerdict(false, "denied", "denied"),
  toolVerdict(true, "ok", ""),
  toolVerdict(false, "boom", ""),
];
console.log(out.join("\n"));
`
	path := filepath.Join(t.TempDir(), "p.js")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	want := "✅ allowed Bash(git status) · ui\n⛔ denied Bash(rm -rf build) · policy · Bash(rm *)\n⛔ denied Edit\n✅ allowed Bash(ls) · ui\n✅ allowed Bash(ls) · ui\ntrue\nfalse\ndenied\nok\nerror"
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
