//go:build !linux

package permbroker

// peerStrict keeps the uid check on systems without /proc ancestry.
// The Linux build also requires the pinned hook under the launched CLI.
func (e *Engine) peerStrict(int, string) bool {
	return true
}
