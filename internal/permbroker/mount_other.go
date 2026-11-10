//go:build !linux

package permbroker

// mountMismatch is unused off Linux. Darwin keeps the device id.
func mountMismatch(target, root string) (bool, bool) {
	return false, true
}
