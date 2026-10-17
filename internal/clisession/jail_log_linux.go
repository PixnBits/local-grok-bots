//go:build linux && !lgbtest

package clisession

// hostJailLogKey is false in a production build. Test log paths are not
// bind-mounted into the jail.
func hostJailLogKey(string) bool { return false }
