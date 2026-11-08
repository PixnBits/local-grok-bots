package github

import (
	"errors"
	"strings"
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
	listed, err := Classify("api", "/repos/acme/widgets/issues", "per_page=10&page=1&state=open", allow)
	if err != nil || listed.Query != "page=1&per_page=10&state=open" {
		t.Fatalf("issue query %#v %v", listed, err)
	}
	if _, err := Classify("api", "/repos/acme/widgets/issues", "state=closed", allow); err == nil {
		t.Fatal("accepted state=closed")
	}
	if _, err := Classify("api", "/repos/acme/widgets/issues", "page=1&page=2", allow); err == nil {
		t.Fatal("accepted duplicate page")
	}
	files, err := Classify("api", "/repos/acme/widgets/pulls/7/files", "page=2&per_page=10", allow)
	if err != nil || files.Query != "page=2&per_page=10" {
		t.Fatalf("files query %#v %v", files, err)
	}
	sha := strings.Repeat("a", 40)
	checks, err := Classify("api", "/repos/acme/widgets/commits/"+sha+"/check-runs", "page=1&per_page=10", allow)
	if err != nil || checks.Query != "page=1&per_page=10" {
		t.Fatalf("checks query %#v %v", checks, err)
	}
	if _, err := Classify("api", "/repos/Acme/Widgets.git", "", allow); err == nil {
		t.Fatal("accepted .git on api")
	}
	mixed := allowMap("aCmE/wIdGeTs")
	got, err = Classify("github", "/AcMe/WiDgEtS.git/info/refs", "service=git-upload-pack", mixed)
	if err != nil || got.Owner != "acme" || got.Repo != "widgets" {
		t.Fatalf("mixed allow %#v %v", got, err)
	}
	api, err = Classify("api", "/repos/AcMe/WiDgEtS", "", mixed)
	if err != nil || api.Owner != "acme" || api.Repo != "widgets" {
		t.Fatalf("mixed api %#v %v", api, err)
	}
	if _, err := Classify("github", "/Other/Widgets.git/info/refs", "service=git-upload-pack", mixed); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("mixed miss: %v", err)
	}
}
