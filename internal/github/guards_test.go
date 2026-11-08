package github

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadGuards(t *testing.T) {
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/widgets/issues":
			io.WriteString(w, `[
				{"number":1,"title":"Open","state":"open","body":"a","html_url":"https://github.com/acme/widgets/issues/1","user":{"login":"ada bad"}},
				{"number":2,"title":"Shut","state":"closed","body":"z","html_url":"https://github.com/acme/widgets/issues/2","user":{"login":"bea"}},
				{"number":3,"title":"Foreign","state":"open","body":"q","html_url":"https://github.com/other/widgets/issues/3","user":{"login":"bea"}}
			]`)
		case "/repos/acme/widgets/issues/7":
			io.WriteString(w, `{"number":7,"title":"Odd","state":"locked","body":"x","html_url":"https://github.com/acme/widgets/issues/7","user":{"login":"ada"}}`)
		case "/repos/acme/widgets/issues/8":
			io.WriteString(w, `{"number":8,"title":"Moved","state":"open","body":"x","html_url":"https://github.com/other/repo/issues/8","user":{"login":"ada"}}`)
		case "/repos/acme/widgets/issues/4/comments":
			io.WriteString(w, `[{"id":9,"body":"nope","html_url":"https://github.com/other/widgets/issues/4#issuecomment-9","user":{"login":"bea"}}]`)
		case "/repos/acme/widgets/issues/7/comments":
			io.WriteString(w, `[]`)
		case "/repos/acme/widgets/pulls/7":
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7","title":"T","body":"B","state":"open","head":{"ref":"feature","sha":"`+sha+`"},"base":{"ref":"main"}}`)
		case "/repos/acme/widgets/pulls/7/files":
			io.WriteString(w, `[]`)
		case "/repos/acme/widgets/pulls/7/reviews":
			io.WriteString(w, `[]`)
		case "/repos/acme/widgets/pulls/7/comments":
			io.WriteString(w, `[{"user":{"login":"ada bad"},"path":"a.go","line":-5,"body":"nit","diff_hunk":"@@"}]`)
		case "/repos/acme/widgets/commits/" + sha + "/check-runs":
			io.WriteString(w, `{"total_count":1,"check_runs":[{"name":"ci","status":"completed","conclusion":"success!"}]}`)
		case "/repos/acme/widgets/commits/" + sha + "/status":
			io.WriteString(w, `{"state":"failure","statuses":[{"context":"ci/legacy-required","state":"failure"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	lim := Limits{PerPage: 10, MaxItems: 10, MaxPages: 1}
	if _, _, err := ListOpenIssues(ctx, srv.Client(), srv.URL, "acme", "widgets", lim); err == nil {
		t.Fatal("foreign issue was listed")
	}
	if _, err := GetIssue(ctx, srv.Client(), srv.URL, "acme", "widgets", 7); err == nil || !strings.Contains(err.Error(), "github response") {
		t.Fatalf("bad state %v", err)
	}
	if _, err := GetIssue(ctx, srv.Client(), srv.URL, "acme", "widgets", 8); err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("moved issue %v", err)
	}
	if _, _, err := ListIssueComments(ctx, srv.Client(), srv.URL, "acme", "widgets", 4, lim); err == nil {
		t.Fatal("foreign comment accepted")
	}
	detail, err := ReadPull(ctx, srv.Client(), srv.URL, "acme", "widgets", 7, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Comments) != 1 || detail.Comments[0].Line != 0 || detail.Comments[0].User != "" {
		t.Fatalf("review comment %+v", detail.Comments)
	}
	if len(detail.Checks) != 1 || detail.Checks[0].Conclusion != "" || strings.Contains(detail.Checks[0].Conclusion, "!") {
		t.Fatalf("conclusion %+v", detail.Checks)
	}
	if detail.CombinedState != "failure" || len(detail.Statuses) != 1 || detail.Statuses[0].Conclusion != "failure" || detail.Statuses[0].Source != "status" {
		t.Fatalf("statuses %+v state %q", detail.Statuses, detail.CombinedState)
	}
	if safeLogin("ada bad") != "" || safeToken("success!") != "" || safeToken("bad state!") != "" {
		t.Fatal("unsafe token passed through")
	}
}

func TestListSkipsClosedWhenAlone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"number":2,"title":"Shut","state":"closed","body":"z","html_url":"https://github.com/acme/widgets/issues/2","user":{"login":"bea"}}]`)
	}))
	defer srv.Close()
	got, _, err := ListOpenIssues(context.Background(), srv.Client(), srv.URL, "acme", "widgets", Limits{PerPage: 10, MaxItems: 10, MaxPages: 1})
	if err != nil || len(got) != 0 {
		t.Fatalf("closed issue leaked: %v %+v", err, got)
	}
}

func TestCreateCommentRejectsForeignURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"id":15,"html_url":"https://github.com/other/widgets/issues/7#issuecomment-15"}`)
	}))
	defer srv.Close()
	got, err := CreateComment(context.Background(), srv.Client(), srv.URL+"/repos/acme/widgets/issues/7/comments", "acme", "widgets", 7, "hello")
	if err == nil || got.URL != "" || strings.Contains(got.URL, "other") {
		t.Fatalf("foreign comment url returned: %+v %v", got, err)
	}
	var api *APIError
	if !errors.As(err, &api) || !api.Unverified() {
		t.Fatalf("want unverified, got %v", err)
	}
}

func TestPostTimeoutIsUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := doGitHub(ctx, srv.Client(), http.MethodPost, srv.URL+"/repos/acme/widgets/issues", map[string]any{"title": "T"}, http.StatusCreated)
	var api *APIError
	if !errors.As(err, &api) || !api.Unverified() {
		t.Fatalf("post timeout %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = doGitHub(ctx, srv.Client(), http.MethodGet, srv.URL+"/repos/acme/widgets/issues/1", nil, http.StatusOK)
	if !errors.As(err, &api) || api.Unverified() || err.Error() != "github unavailable" {
		t.Fatalf("get timeout %v", err)
	}
}

func TestConnectionRefusedStaysUnavailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:18797")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	client := &http.Client{Timeout: time.Second}
	_, err = doGitHub(context.Background(), client, http.MethodPost, "http://127.0.0.1:18797/repos/acme/widgets/issues", map[string]any{"title": "T"}, http.StatusCreated)
	var api *APIError
	if !errors.As(err, &api) || api.Unverified() || err.Error() != "github unavailable" {
		t.Fatalf("refused post %v", err)
	}
}

func TestGitOnlyJailProxy(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	p, err := New(Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return tokenSecret, nil },
		GitBase: up.URL,
		APIBase: up.URL,
		GitOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p)
	defer srv.Close()
	check := func(method, path string, want int) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("%s %s -> %d, want %d", method, path, res.StatusCode, want)
		}
	}
	check(http.MethodGet, "/api/repos/acme/widgets/issues?state=open&per_page=10&page=1", http.StatusForbidden)
	check(http.MethodGet, "/api/repos/acme/widgets/pulls/7", http.StatusForbidden)
	check(http.MethodGet, "/api/repos/acme/widgets", http.StatusNoContent)
	check(http.MethodPost, "/github/acme/widgets.git/git-upload-pack", http.StatusNoContent)
}
