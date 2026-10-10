package web

import _ "embed"

// IndexHTML is the single-page client served by the daemon.
//
//go:embed index.html
var IndexHTML []byte
