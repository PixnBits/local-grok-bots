//go:build !unix

package daemon

import (
	"context"
	"errors"
)

// repoHandle is unused off unix. Resolve fails closed.
type repoHandle struct{}

func (h *repoHandle) Close() error { return nil }

func (h *repoHandle) configReason() string { return "config" }

func (h *repoHandle) stable() bool { return false }

func copyGitMirror(context.Context, string, *repoHandle) (string, error) {
	return "", errors.New("mirror")
}

func resolveWorkspaceRepo(string, string) (*repoHandle, string) {
	return nil, "repository not found in workspace"
}
