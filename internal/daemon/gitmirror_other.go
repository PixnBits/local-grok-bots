//go:build !unix

package daemon

import "errors"

func workspaceConfigReason(string) string { return "config" }

func copyGitMirror(string, string) (string, error) {
	return "", errors.New("mirror")
}

func resolveWorkspaceRepo(string, string) (string, string) {
	return "", "repository not found in workspace"
}
