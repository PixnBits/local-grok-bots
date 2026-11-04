//go:build !linux

package sandbox

func probedSafeSignal() bool { return false }
