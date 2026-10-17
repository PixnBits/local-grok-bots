//go:build linux && lgbtest

package clisession

// hostJailLogKey is the test-only allowlist for log files a stub CLI writes
// outside the workspace. A production build does not include this file.
func hostJailLogKey(k string) bool {
	switch k {
	case "LGB_ENV_LOG", "LGB_ARGV_LOG", "LGB_FIXTURE", "LGB_AUTH_LOG":
		return true
	}
	return false
}
