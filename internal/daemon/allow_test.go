package daemon

import "testing"

func TestRepoAllowedFold(t *testing.T) {
	repos := []string{"aCmE/wIdGeTs"}
	if !repoAllowed(repos, "AcMe", "WiDgEtS") {
		t.Fatal("mixed owner and repo were refused")
	}
	if !repoAllowed(repos, "acme", "widgets") {
		t.Fatal("lower owner and repo were refused")
	}
	if repoAllowed(repos, "acme", "other") || repoAllowed(repos, "other", "widgets") {
		t.Fatal("a different repository was allowed")
	}
	if repoAllowed(nil, "acme", "widgets") {
		t.Fatal("empty allowlist allowed a repository")
	}
}
