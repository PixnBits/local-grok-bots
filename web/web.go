package web

import _ "embed"

// IndexHTML is the single-page client served by the daemon.
// Scripts and styles are separate files so the page can send a CSP
// without inline script or style.
//
//go:embed index.html
var IndexHTML []byte

//go:embed app.css
var AppCSS []byte

//go:embed theme.js
var ThemeJS []byte

//go:embed app.js
var AppJS []byte

//go:embed favicon.svg
var FaviconSVG []byte

//go:embed favicon.ico
var FaviconICO []byte

//go:embed apple-touch-icon.png
var AppleTouchIcon []byte

// ClientSource is the page plus its scripts and styles. Tests that
// used to read one file still find markers and selectors here.
func ClientSource() string {
	return string(IndexHTML) + "\n" + string(AppCSS) + "\n" + string(ThemeJS) + "\n" + string(AppJS)
}
