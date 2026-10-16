package web

import (
	"strings"
	"testing"
)

// Marks render inside buttons (inline-block), shape buttons are labelled,
// off-palette colours get a swatch, and the thread header and profile
// heading show the mark. Picking a shape or colour paints the heading mark.
// Shape and colour groups keep their labels. There is no preview row.
func TestMarkMarkup(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		"display: inline-block; vertical-align: middle;",
		".shape-btn { display: inline-flex; align-items: center; justify-content: center; }",
		"box-shadow: inset 0 0 0 1px",
		`b.setAttribute("aria-label", SHAPE_NAMES[shape] || shape)`,
		`"Custom " + color`,
		`id="color-custom"`,
		`id="thread-mark"`,
		".mark[hidden] { display: none; }",
		`id="profile-head-mark"`,
		`id="profile-head-name"`,
		`paintMark($("#profile-head-mark"), state.mark)`,
		`role="group" aria-label="Mark shape"`,
		`role="group" aria-label="Mark colour"`,
		`el("small", "bot-attn", words)`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	for _, s := range []string{
		`id="profile-mark"`,
		`<strong>Mark</strong>`,
		`paintMark($("#profile-mark"), state.mark)`,
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has the mark preview %q", s)
		}
	}
}
