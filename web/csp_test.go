package web

import (
	"strings"
	"testing"
)

func TestNoInlineCSP(t *testing.T) {
	src := string(IndexHTML)
	if strings.Contains(src, "<style") || strings.Contains(src, "<script>") {
		t.Fatal("index.html has an inline script or style")
	}
	if strings.Contains(src, " style=") {
		t.Fatal("index.html has an inline style attribute")
	}
	if !strings.Contains(src, `src="/theme.js"`) || !strings.Contains(src, `href="/app.css"`) || !strings.Contains(src, `src="/app.js"`) {
		t.Fatal("page does not load the same-origin assets")
	}
	js := string(AppJS)
	if strings.Contains(js, "use one `*` for each word") || strings.Contains(js, "use one * for each word") {
		t.Fatal("pattern help still says to use one star for each word")
	}
	if !strings.Contains(js, "A * stands for exactly one word and cannot be last.") {
		t.Fatal("pattern help does not match the validator")
	}
}
