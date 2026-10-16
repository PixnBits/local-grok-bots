//go:build !unix

package coi

func dirIdentity(string) (uint64, uint64, error) {
	return 0, 0, ErrSandboxUnavailable
}
