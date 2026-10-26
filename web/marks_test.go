package web

import (
	"strings"
	"testing"
)

// Marks render inside buttons (inline-block), shape buttons are labelled,
// off-palette colours get a swatch, and the thread header and profile
// heading show the mark. Picking a shape or colour paints the heading mark.
// Shape and colour groups keep their labels. There is no preview row.
// Every shape has an underlay edge, because clip-path drops an inset shadow.
// The profile heading reads the bot name, including while it is typed.
// At phone width the preset swatches fill a grid and the custom control sits on the next row.
func TestMarkMarkup(t *testing.T) {
	src := string(IndexHTML)
	for _, s := range []string{
		"display: inline-block; vertical-align: middle;",
		"width: 28px; height: 28px; flex: none;",
		".shape-btn { display: inline-flex; align-items: center; justify-content: center; }",
		"box-shadow: inset 0 0 0 1px",
		".mark::before { background: var(--mark-edge); }",
		".mark::after { inset: 2px; background: var(--c, var(--mark-fallback)); }",
		`.mark[data-shape="circle"]::before`,
		`.mark[data-shape="square"]::before`,
		`.mark[data-shape="diamond"]::before`,
		`.mark[data-shape="triangle"]::before`,
		`.mark[data-shape="hex"]::before`,
		`.mark[data-shape="triangle"]::after { clip-path: polygon(50% 0, 100% 100%, 0 100%); }`,
		`.mark[data-shape="hex"]::after { clip-path: polygon(25% 6%, 75% 6%, 100% 50%, 75% 94%, 25% 94%, 0 50%); }`,
		`b.setAttribute("aria-label", SHAPE_NAMES[shape] || shape)`,
		`"Current colour " + color`,
		`id="color-custom"`,
		`id="thread-mark"`,
		".mark[hidden] { display: none; }",
		`id="profile-head-mark"`,
		`id="profile-head-name"`,
		`paintMark($("#profile-head-mark"), state.mark)`,
		`role="group" aria-label="Mark shape"`,
		`role="group" aria-label="Mark colour"`,
		`el("small", "bot-attn", words)`,
		`function syncProfileHeadingName()`,
		`$("#profile-name").addEventListener("input", syncProfileHeadingName)`,
		`$("#profile-head-name").textContent = name || "Profile"`,
		`const name = $("#profile-name").value.trim()`,
		`@media (max-width: 540px)`,
		`grid-template-columns: repeat(9, minmax(0, 1fr))`,
		`.colours:has(.swatch:nth-child(9)) { grid-template-columns: repeat(10, minmax(0, 1fr)); }`,
		`<label class="color-custom" for="color-custom">Custom colour</label>`,
	} {
		if !strings.Contains(src, s) {
			t.Errorf("index.html missing %q", s)
		}
	}
	for _, s := range []string{
		`id="profile-mark"`,
		`<strong>Mark</strong>`,
		`paintMark($("#profile-mark"), state.mark)`,
		`aria-label="Profile"`,
		`box-shadow: inset 0 0 0 1px rgba(0,0,0,.22);
  }
  .mark[data-shape="circle"]`,
	} {
		if strings.Contains(src, s) {
			t.Errorf("index.html still has %q", s)
		}
	}
	if strings.Contains(src, `<h2 class="profile-head" aria-label`) {
		t.Error("profile heading must not replace its name with an aria-label")
	}
}
