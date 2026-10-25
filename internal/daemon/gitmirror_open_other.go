//go:build unix && !linux

package daemon

// openChain resolves parts from rootFd with a component walk. Each step is
// an O_NOFOLLOW open relative to the previous directory descriptor.
func openChain(rootFd int, parts []string) ([]heldDir, error) {
	return openChainWalk(rootFd, parts)
}
