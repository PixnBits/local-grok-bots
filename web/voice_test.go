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

// Voice helpers run under node when node is installed.
func TestVoiceHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	src := string(IndexHTML)
	i := strings.Index(src, "// voice:begin")
	j := strings.Index(src, "// voice:end")
	if i < 0 || j < i {
		t.Fatal("voice markers missing from index.html")
	}
	js := src[i:j] + `
console.log(JSON.stringify({
  speak: speakableText("# Title\n**Bold** and [link](https://x.y) with ` + "`code`" + `\n` + "```go\\nx := 1\\n```" + `\n- item"),
  small: voiceDeviceProfile({hardwareConcurrency:4, deviceMemory:2}).heavyOK,
  big: voiceDeviceProfile({hardwareConcurrency:16, deviceMemory:8, gpu:{}}).heavyOK,
  summarizeGone: typeof voiceSummaryPrompt === "undefined",
}));`
	path := filepath.Join(t.TempDir(), "v.js")
	if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	var got struct {
		Speak         string
		Small, Big    bool
		SummarizeGone bool
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode %v: %s", err, out)
	}
	if got.Speak != "Title Bold and link with code (code omitted) item" {
		t.Errorf("speak %q", got.Speak)
	}
	if !got.SummarizeGone {
		t.Error("voiceSummaryPrompt should be removed")
	}
	if got.Small || !got.Big {
		t.Errorf("profile small=%v big=%v", got.Small, got.Big)
	}
}
