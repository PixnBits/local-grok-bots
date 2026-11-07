package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestFaviconLinks(t *testing.T) {
	html := string(IndexHTML)
	links := []string{
		`<link rel="icon" href="/favicon.ico" sizes="32x32">`,
		`<link rel="icon" type="image/svg+xml" href="/favicon.svg">`,
		`<link rel="apple-touch-icon" href="/apple-touch-icon.png">`,
	}
	for _, tag := range links {
		if !strings.Contains(html, tag) {
			t.Errorf("missing %s", tag)
		}
	}
	want := "</title>\n" + strings.Join(links, "\n")
	if !strings.Contains(html, want) {
		t.Fatal("favicon links do not follow </title>")
	}
}

func TestFaviconEmbeds(t *testing.T) {
	if len(FaviconSVG) == 0 {
		t.Fatal("FaviconSVG is empty")
	}
	if len(FaviconICO) == 0 {
		t.Fatal("FaviconICO is empty")
	}
	if len(AppleTouchIcon) == 0 {
		t.Fatal("AppleTouchIcon is empty")
	}
	svg := strings.TrimSpace(string(FaviconSVG))
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("FaviconSVG starts with %q", svg[:min(len(svg), 16)])
	}
	if !bytes.HasPrefix(FaviconICO, []byte{0x00, 0x00, 0x01, 0x00}) {
		t.Fatal("FaviconICO missing ICO magic")
	}
	if !bytes.HasPrefix(AppleTouchIcon, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("AppleTouchIcon missing PNG magic")
	}
	for _, bad := range []string{"href", "@import", "url("} {
		if strings.Contains(svg, bad) {
			t.Errorf("FaviconSVG contains %q", bad)
		}
	}
	stripped := strings.ReplaceAll(svg, "http://www.w3.org/2000/svg", "")
	for _, scheme := range []string{"http://", "https://"} {
		if strings.Contains(stripped, scheme) {
			t.Errorf("FaviconSVG contains %s outside xmlns", scheme)
		}
	}
}
