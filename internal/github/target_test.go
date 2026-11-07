package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupTargetPullNumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/widgets/issues/7":
			ioWrite(w, `{"number":7,"title":"Other","state":"open","html_url":"https://github.com/acme/widgets/pull/999"}`)
		case "/repos/acme/widgets/issues/8":
			ioWrite(w, `{"number":8,"title":"Mine","state":"open","body":"x","html_url":"https://github.com/acme/widgets/pull/8","user":{"login":"ada"}}`)
		case "/repos/acme/widgets/issues/9":
			ioWrite(w, `{"number":9,"title":"Foreign","state":"open","body":"x","html_url":"https://github.com/other/widgets/pull/9","user":{"login":"ada"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	if _, err := LookupTarget(context.Background(), client, srv.URL, "acme", "widgets", 7); err == nil {
		t.Fatal("accepted a different pull number")
	}
	got, err := LookupTarget(context.Background(), client, srv.URL, "acme", "widgets", 8)
	if err != nil || got.Kind != "pull" || !strings.HasSuffix(got.URL, "/pull/8") {
		t.Fatalf("%v %#v", err, got)
	}
	_, err = GetIssue(context.Background(), client, srv.URL, "acme", "widgets", 8)
	if err == nil || !strings.Contains(err.Error(), "pull request") || strings.Contains(err.Error(), "moved") {
		t.Fatal(err)
	}
	_, err = GetIssue(context.Background(), client, srv.URL, "acme", "widgets", 9)
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatal(err)
	}
}

func ioWrite(w http.ResponseWriter, s string) {
	_, _ = w.Write([]byte(s))
}
