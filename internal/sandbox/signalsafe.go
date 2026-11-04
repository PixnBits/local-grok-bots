package sandbox

import "sync/atomic"

// safeChoice overrides SafeSignalSupported in tests. set is false until a
// test stores one.
type safeChoice struct {
	set bool
	ok  bool
}

var safeSignalChoice atomic.Value // safeChoice

// SetSafeSignalSupportedForTest forces SafeSignalSupported until restore runs.
// A nil-like restore clears the override and the probe is used again.
func SetSafeSignalSupportedForTest(ok bool) (restore func()) {
	safeSignalChoice.Store(safeChoice{set: true, ok: ok})
	return func() { safeSignalChoice.Store(safeChoice{}) }
}

// SafeSignalSupported reports whether Trim can signal through pidfds.
// The probe runs once. A test override skips the probe.
func SafeSignalSupported() bool {
	if v := safeSignalChoice.Load(); v != nil {
		if c, ok := v.(safeChoice); ok && c.set {
			return c.ok
		}
	}
	return probedSafeSignal()
}
