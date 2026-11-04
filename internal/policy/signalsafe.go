package policy

import (
	"sync/atomic"
	"time"
)

// shellSignalCeiling is the shell timeout cap when pidfd signalling is unavailable.
const shellSignalCeiling = 30 * time.Second

const shellSignalWarning = "shell timeouts above 30s are unavailable on this system; the ceiling is 30s"

const shellSignalSource = "this system"

// shellSignalFn, when set, reports whether shell timeouts above 30s are safe.
// Unset means they are allowed, so policy tests keep values above 30s.
var shellSignalFn atomic.Value // func() bool

// UseShellSignal installs the probe the daemon uses. A nil probe allows
// timeouts above 30s. The daemon passes sandbox.SafeSignalSupported before Load.
func UseShellSignal(fn func() bool) {
	if fn == nil {
		shellSignalFn.Store(func() bool { return true })
		return
	}
	shellSignalFn.Store(fn)
}

func shellSignalSupported() bool {
	v := shellSignalFn.Load()
	if v == nil {
		return true
	}
	fn, ok := v.(func() bool)
	if !ok || fn == nil {
		return true
	}
	return fn()
}

// NoteShellSignalWarning appends the 30s warning once when signalling is unavailable.
func (p *Policy) NoteShellSignalWarning() {
	if p == nil || shellSignalSupported() {
		return
	}
	for _, w := range p.Warnings {
		if w == shellSignalWarning {
			return
		}
	}
	p.Warnings = append(p.Warnings, shellSignalWarning)
}
