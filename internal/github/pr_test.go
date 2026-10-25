package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptPullURL(t *testing.T) {
	got, ok := AcceptPullURL("acme", "widgets", "https://github.com/Acme/Widgets/pull/7")
	if !ok || got != "https://github.com/acme/widgets/pull/7" {
		t.Fatalf("url %q %v", got, ok)
	}
	for _, raw := range []string{
		"http://github.com/acme/widgets/pull/7",
		"https://user:tok@github.com/acme/widgets/pull/7",
		"https://github.com/acme/widgets/pull/7?x=1",
		"https://evil.example/acme/widgets/pull/7",
		"https://github.com/other/widgets/pull/7",
		"https://github.com/acme/widgets/pull/0",
		"https://github.com/acme/widgets/pull/7/files",
	} {
		if _, ok := AcceptPullURL("acme", "widgets", raw); ok {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestCreatePullDropsTheBodyOnError(t *testing.T) {
	const leak = "lgb-github-test-secret-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("caller set Authorization")
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"message":"`+leak+`","html_url":"https://evil.example/x"}`)
	}))
	t.Cleanup(srv.Close)
	_, err := CreatePull(context.Background(), nil, srv.URL+"/repos/acme/widgets/pulls", "acme", "widgets", NewPull{
		Title: "Add a widget", Head: "feature", Base: "main", Draft: true,
	})
	if err == nil || err.Error() != "github status 422" || strings.Contains(err.Error(), leak) || strings.Contains(err.Error(), "evil") {
		t.Fatalf("err %v", err)
	}
}

func TestGetPullProjectsFields(t *testing.T) {
	const leak = "lgb-github-test-secret-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"html_url":"https://github.com/acme/widgets/pull/7",
			"state":"open",
			"draft":true,
			"head":{"ref":"feature","sha":"`+leak+`"},
			"base":{"ref":"main","sha":"`+leak+`"},
			"body":"`+leak+`",
			"title":"Add a widget"
		}`)
	}))
	t.Cleanup(srv.Close)
	got, err := GetPull(context.Background(), nil, srv.URL+"/repos/acme/widgets/pulls/7", "acme", "widgets")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://github.com/acme/widgets/pull/7" || got.State != "open" || !got.Draft || got.Head != "feature" || got.Base != "main" {
		t.Fatalf("%+v", got)
	}
}
