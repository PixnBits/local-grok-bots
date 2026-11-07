package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckRunPageSetsTruncated(t *testing.T) {
	sha := strings.Repeat("a", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/check-runs"):
			var b strings.Builder
			b.WriteString(`{"total_count":10,"check_runs":[`)
			for i := 0; i < 10; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"name":"c%d","status":"completed","conclusion":"success"}`, i)
			}
			b.WriteString(`]}`)
			io.WriteString(w, b.String())
		case strings.HasSuffix(r.URL.Path, "/status"):
			io.WriteString(w, `{"state":"success","statuses":[{"context":"ci","state":"success"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	page, err := listChecks(context.Background(), srv.Client(), srv.URL, "acme", "widgets", sha, Limits{PerPage: 10, MaxItems: 10, MaxPages: 1})
	if err != nil || !page.Truncated || len(page.Runs) != 10 {
		t.Fatalf("%v trunc %v runs %d", err, page.Truncated, len(page.Runs))
	}
}

func TestStatusCapSetsTruncated(t *testing.T) {
	sha := strings.Repeat("b", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/check-runs"):
			io.WriteString(w, `{"total_count":1,"check_runs":[{"name":"build","status":"completed","conclusion":"success"}]}`)
		case strings.HasSuffix(r.URL.Path, "/status"):
			var b strings.Builder
			b.WriteString(`{"state":"success","statuses":[`)
			for i := 0; i < 101; i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"context":"ci%d","state":"success"}`, i)
			}
			b.WriteString(`]}`)
			io.WriteString(w, b.String())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	page, err := listChecks(context.Background(), srv.Client(), srv.URL, "acme", "widgets", sha, Limits{PerPage: 10, MaxItems: 10, MaxPages: 1})
	if err != nil || !page.Truncated || len(page.Statuses) != 100 {
		t.Fatalf("%v trunc %v statuses %d", err, page.Truncated, len(page.Statuses))
	}
}

func TestConversationPageSetsTruncated(t *testing.T) {
	sha := strings.Repeat("c", 40)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/repos/acme/widgets/pulls/7":
			fmt.Fprintf(w, `{"html_url":"https://github.com/acme/widgets/pull/7","title":"Add","body":"x","state":"open","head":{"ref":"feature","sha":"%s"},"base":{"ref":"main"}}`, sha)
		case r.URL.Path == "/repos/acme/widgets/pulls/7/files":
			io.WriteString(w, `[{"filename":"a.go","status":"modified","additions":1,"deletions":0,"patch":"+a"}]`)
		case r.URL.Path == "/repos/acme/widgets/pulls/7/reviews":
			io.WriteString(w, `[{"user":{"login":"bea"},"state":"COMMENTED","body":"ok"}]`)
		case r.URL.Path == "/repos/acme/widgets/pulls/7/comments":
			io.WriteString(w, `[{"user":{"login":"bea"},"path":"a.go","line":1,"body":"nit","diff_hunk":"@@"}]`)
		case strings.HasSuffix(r.URL.Path, "/check-runs"):
			io.WriteString(w, `{"total_count":1,"check_runs":[{"name":"build","status":"completed","conclusion":"success"}]}`)
		case strings.HasSuffix(r.URL.Path, "/status"):
			io.WriteString(w, `{"state":"success","statuses":[{"context":"ci","state":"success"}]}`)
		case r.URL.Path == "/repos/acme/widgets/issues/7/comments":
			var b strings.Builder
			b.WriteByte('[')
			for i := 1; i <= 10; i++ {
				if i > 1 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"id":%d,"body":"c","html_url":"https://github.com/acme/widgets/issues/7#issuecomment-%d","user":{"login":"bea"}}`, i, i)
			}
			b.WriteByte(']')
			io.WriteString(w, b.String())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	detail, err := ReadPull(context.Background(), srv.Client(), srv.URL, "acme", "widgets", 7, Limits{PerPage: 10, MaxItems: 10, MaxPages: 1})
	if err != nil || !detail.Truncated || len(detail.Conversation) != 10 || len(detail.Files) != 1 || len(detail.Checks) != 1 {
		t.Fatalf("%v trunc %v conv %d files %d checks %d", err, detail.Truncated, len(detail.Conversation), len(detail.Files), len(detail.Checks))
	}
}
