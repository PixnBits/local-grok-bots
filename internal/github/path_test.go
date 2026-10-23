package github

import (
	"errors"
	"testing"
)

func allowMap(repos ...string) map[string]bool {
	m := map[string]bool{}
	for _, r := range repos {
		m[r] = true
	}
	return m
}

func TestClassifyGitAndAPI(t *testing.T) {
	allow := allowMap("acme/widgets")
	got, err := Classify("github", "/Acme/Widgets.git/info/refs", "service=git-upload-pack", allow)
	if err != nil || got.Owner != "acme" || got.Repo != "widgets" || got.Query != "service=git-upload-pack" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := Classify("github", "/Acme/Widgets.git/git-receive-pack", "", allow); err != nil {
		t.Fatal(err)
	}
	if _, err := Classify("github", "/other/widgets.git/info/refs", "service=git-upload-pack", allow); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("other repo: %v", err)
	}
	for _, raw := range []string{
		"/Acme/Widgets.git/HEAD",
		"/Acme/Widgets.git/info/refs/../../etc",
		"/Acme/%2e%2e/Widgets.git/info/refs",
		"/Acme/Widgets.git/info/refs/extra",
		"Acme/Widgets.git/info/refs",
	} {
		if _, err := Classify("github", raw, "service=git-upload-pack", allow); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := Classify("github", "/Acme/Widgets.git/git-upload-pack", "service=git-upload-pack", allow); err == nil {
		t.Fatal("accepted query on pack")
	}
	if _, err := Classify("github", "/Acme/Widgets.git/info/refs", "service=git-receive-pack&x=1", allow); err == nil {
		t.Fatal("accepted extra query")
	}
	api, err := Classify("api", "/repos/Acme/Widgets/pulls/3", "", allow)
	if err != nil || api.Path != "/repos/Acme/Widgets/pulls/3" {
		t.Fatalf("%#v %v", api, err)
	}
	if _, err := Classify("api", "/repos/Acme/Other", "", allow); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("api other: %v", err)
	}
	if _, err := Classify("api", "/user", "", allow); err == nil {
		t.Fatal("accepted /user")
	}
	if _, err := Classify("api", "/repos/Acme/Widgets", "page=2", allow); err == nil {
		t.Fatal("accepted api query")
	}
	if _, err := Classify("api", "/repos/Acme/Widgets.git", "", allow); err == nil {
		t.Fatal("accepted .git on api")
	}
}
