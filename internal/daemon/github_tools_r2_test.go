package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PixnBits/local-grok-bots/internal/audit"
	"github.com/PixnBits/local-grok-bots/internal/model"
	"github.com/PixnBits/local-grok-bots/internal/permission"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func TestWindowTextRuneBoundary(t *testing.T) {
	s := strings.Repeat("a", 4095) + "é" + "TAIL"
	chunk, total, _, next, more := windowText(s, 0, 4096)
	if !more || next != 4095 || total != len(s) || !utf8.ValidString(chunk) || strings.Contains(chunk, "é") {
		t.Fatalf("first window more %v next %d %q", more, next, chunk)
	}
	rest, _, _, _, more2 := windowText(s, next, 4096)
	if more2 || chunk+rest != s || !utf8.ValidString(rest) {
		t.Fatalf("second window %q more %v", rest, more2)
	}
	mid, _, snapped, _, _ := windowText(s, 4096, 4096)
	if snapped != 4095 || !strings.HasPrefix(mid, "é") || !utf8.ValidString(mid) {
		t.Fatalf("mid-rune snap %d %q", snapped, mid)
	}
}

func TestGitHubRound2(t *testing.T) {
	const leak = "lgb-github-test-secret-value"
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	longPatch := strings.Repeat("a", 4095) + "é" + "TAIL"
	var mode atomic.Value
	mode.Store("ok")
	var hits atomic.Int32
	var posts atomic.Int32
	var lastPost atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if r.Method == http.MethodPost {
			posts.Add(1)
			lastPost.Store(string(rawBody))
		}
		if r.Header.Get("Authorization") != "Bearer "+leak {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		page := 1
		if n := r.URL.Query().Get("page"); n != "" {
			page = int(n[0] - '0')
			if len(n) > 1 {
				page = 0
				for _, c := range n {
					page = page*10 + int(c-'0')
				}
			}
		}
		per := 10
		if n := r.URL.Query().Get("per_page"); n != "" {
			per = 0
			for _, c := range n {
				per = per*10 + int(c-'0')
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if mode.Load() == "heavy" && r.Method == http.MethodGet && writeHeavyPage(w, r.URL.Path, sha) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets":
			io.WriteString(w, `{"default_branch":"main"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues" && mode.Load() == "token":
			io.WriteString(w, `[{"number":1,"title":"`+leak+`","state":"open","body":"safe","html_url":"https://github.com/acme/widgets/issues/1","user":{"login":"ada"}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues":
			io.WriteString(w, `[{"number":1,"title":"Empty state","state":"open","body":"short","html_url":"https://github.com/acme/widgets/issues/1","user":{"login":"ada"}}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7" && mode.Load() == "missing":
			http.NotFound(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7" && mode.Load() == "rtl-title":
			io.WriteString(w, `{"number":7,"title":"ab`+"\u202E"+`cd","state":"open","body":"x","html_url":"https://github.com/acme/widgets/issues/7","user":{"login":"ada"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7" && mode.Load() == "long-title":
			io.WriteString(w, `{"number":7,"title":`+quoteJSON(strings.Repeat("A", 2001))+`,"state":"open","body":"x","html_url":"https://github.com/acme/widgets/issues/7","user":{"login":"ada"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7" && mode.Load() == "pull-url":
			io.WriteString(w, `{"number":7,"title":"A pull","state":"open","body":"x","html_url":"https://github.com/acme/widgets/pull/7","user":{"login":"ada"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7":
			io.WriteString(w, `{"number":7,"title":"Empty state","state":"open","body":"the list is blank","html_url":"https://github.com/acme/widgets/issues/7","user":{"login":"ada"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/issues/7/comments":
			writeR2Comments(w, page, per)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7":
			body := "Fixes the empty state."
			if mode.Load() == "angle" {
				body = "a <tag> & more"
			}
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7","title":"Add a widget","body":`+quoteJSON(body)+`,"state":"open","head":{"ref":"feature","sha":"`+sha+`"},"base":{"ref":"main"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/files" && mode.Load() == "patch":
			io.WriteString(w, `[{"filename":"a.go","status":"modified","additions":1,"deletions":0,"patch":`+quoteJSON(longPatch)+`}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/files" && mode.Load() == "manyfiles":
			writeR2Files(w, page, per)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/files":
			io.WriteString(w, `[{"filename":"a.go","status":"modified","additions":1,"deletions":0,"patch":"+new"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/reviews":
			io.WriteString(w, `[]`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls/7/comments":
			io.WriteString(w, `[]`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/check-runs"):
			if page >= 2 {
				io.WriteString(w, `{"total_count":12,"check_runs":[{"name":"lint-page-2","status":"completed","conclusion":"failure"}]}`)
				return
			}
			io.WriteString(w, `{"total_count":1,"check_runs":[{"name":"build","status":"completed","conclusion":"success"},{"name":"lint","status":"completed","conclusion":"success"},{"name":"test","status":"in_progress","conclusion":null}]}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status"):
			io.WriteString(w, `{"state":"failure","statuses":[{"context":"ci/legacy-required","state":"failure"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues" && mode.Load() == "html":
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, "<html>created</html>")
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues" && mode.Load() == "boom":
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"message":"no"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues":
			if strings.Contains(string(rawBody), leak) {
				http.Error(w, "echo", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"number":4,"html_url":"https://github.com/acme/widgets/issues/4"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments") && mode.Load() == "badurl":
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"id":15,"html_url":"https://github.com/other/widgets/issues/7#issuecomment-15"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comments"):
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"id":15,"html_url":"https://github.com/acme/widgets/issues/7#issuecomment-15"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"html_url":"https://github.com/acme/widgets/pull/7"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	prev := readGitHubToken
	readGitHubToken = func(string) (string, error) {
		return leak, nil
	}
	t.Cleanup(func() { readGitHubToken = prev })

	type env struct {
		app   *App
		bot   store.Bot
		url   string
		evals *atomic.Int32
		audit string
		lg    *audit.Logger
	}
	newEnv := func(t *testing.T, grants []string) env {
		t.Helper()
		app := newApp(t, "", fakeModel{fn: func(model.ChatRequest) (model.ChatResponse, error) {
			return model.ChatResponse{Content: "no"}, nil
		}})
		app.githubAPIBase = upstream.URL
		app.editPol(func(p *policy.Policy) {
			p.GitHub.Repos = []string{"acme/widgets"}
			p.GitHub.TokenFile = "/etc/local-grok-bots/github.token"
			p.UIPrompts = true
			p.PromptTimeout = 15 * time.Second
		})
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		lg, err := audit.Open(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lg.Close() })
		app.audit = lg
		var evals atomic.Int32
		app.perm.AddHook(func(req permission.Request) permission.HookResult {
			if req.Tool == "create_issue" || req.Tool == "create_comment" || req.Tool == "create_pr" {
				evals.Add(1)
			}
			return permission.HookResult{}
		})
		srv := serve(t, app)
		if grants == nil {
			grants = []string{"github"}
		}
		bot := createGrantedBot(t, srv.URL, "Ada", grants)
		if len(grants) == 1 && grants[0] == "github" {
			res, b := do(t, "PATCH", srv.URL+"/api/bots/"+bot.ID, map[string]any{"github_allow": []string{"acme/widgets"}}, "")
			if res.StatusCode != 200 {
				t.Fatalf("allow %d %s", res.StatusCode, b)
			}
		}
		return env{app: app, bot: bot, url: srv.URL, evals: &evals, audit: auditPath, lg: lg}
	}
	bodyOf := func(t *testing.T, args map[string]any) string {
		t.Helper()
		s, _ := args["body"].(string)
		return s
	}

	t.Run("cards show the full body", func(t *testing.T) {
		mode.Store("ok")
		body := strings.Repeat("a", 2200) + "HIDDEN-TAIL-é"
		for _, tc := range []struct {
			tool string
			args map[string]any
		}{
			{"create_issue", map[string]any{"repo": "acme/widgets", "title": "Empty state", "body": body}},
			{"create_comment", map[string]any{"repo": "acme/widgets", "number": float64(7), "body": body}},
			{"create_pr", map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Add a widget", "body": body}},
		} {
			t.Run(tc.tool, func(t *testing.T) {
				e := newEnv(t, nil)
				before := posts.Load()
				outCh := make(chan string, 1)
				errCh := make(chan error, 1)
				go func() {
					out, err := e.app.dispatchTool(t.Context(), e.bot, tc.tool, tc.args)
					outCh <- out
					errCh <- err
				}()
				card := waitCardArgs(t, e.app, e.bot.ID, tc.tool)
				if bodyOf(t, card) != body {
					t.Fatalf("card body %q", bodyOf(t, card))
				}
				if tc.tool == "create_comment" {
					n, ok := card["number"].(float64)
					title, _ := card["target_title"].(string)
					if !ok || n != 7 || title != "Empty state" {
						t.Fatalf("comment card %#v", card)
					}
				}
				if e.app.writeProxyUp() {
					t.Fatal("write proxy up before approval")
				}
				decideCard(t, e.app, e.bot.ID, tc.tool)
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
				<-outCh
				posted, _ := lastPost.Load().(string)
				if posts.Load() != before+1 || !strings.Contains(posted, body) {
					t.Fatalf("posts %d posted tail %v", posts.Load()-before, strings.Contains(posted, "HIDDEN-TAIL-é"))
				}
			})
		}
	})

	t.Run("multibyte body at the limit is posted whole", func(t *testing.T) {
		mode.Store("ok")
		body := strings.Repeat("a", 65534) + "é"
		if len(body) != 1<<16 {
			t.Fatalf("len %d", len(body))
		}
		for _, tc := range []struct {
			tool string
			args map[string]any
		}{
			{"create_issue", map[string]any{"repo": "acme/widgets", "title": "Edge", "body": body}},
			{"create_comment", map[string]any{"repo": "acme/widgets", "number": float64(7), "body": body}},
			{"create_pr", map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Edge", "body": body}},
		} {
			t.Run(tc.tool, func(t *testing.T) {
				e := newEnv(t, nil)
				before := posts.Load()
				errCh := make(chan error, 1)
				go func() {
					_, err := e.app.dispatchTool(t.Context(), e.bot, tc.tool, tc.args)
					errCh <- err
				}()
				card := waitCardArgs(t, e.app, e.bot.ID, tc.tool)
				if bodyOf(t, card) != body || !utf8.ValidString(bodyOf(t, card)) {
					t.Fatal("card split the rune or dropped the tail")
				}
				decideCard(t, e.app, e.bot.ID, tc.tool)
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
				posted, _ := lastPost.Load().(string)
				if posts.Load() != before+1 || !strings.Contains(posted, body) || !utf8.ValidString(posted) {
					t.Fatalf("%s posts %d contains %v", tc.tool, posts.Load()-before, strings.Contains(posted, body))
				}
			})
		}
	})

	t.Run("over-limit body is refused before any write", func(t *testing.T) {
		mode.Store("ok")
		body := strings.Repeat("a", 65535) + "é"
		for _, tc := range []struct {
			tool string
			args map[string]any
		}{
			{"create_issue", map[string]any{"repo": "acme/widgets", "title": "Too big", "body": body}},
			{"create_comment", map[string]any{"repo": "acme/widgets", "number": float64(7), "body": body}},
			{"create_pr", map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Too big", "body": body}},
		} {
			t.Run(tc.tool, func(t *testing.T) {
				e := newEnv(t, nil)
				before := hits.Load()
				_, err := e.app.dispatchTool(t.Context(), e.bot, tc.tool, tc.args)
				if err == nil || e.evals.Load() != 0 || hits.Load() != before {
					t.Fatalf("%s err %v evals %d hits %d", tc.tool, err, e.evals.Load(), hits.Load()-before)
				}
			})
		}
	})

	t.Run("comment pages have no gaps", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		var got []string
		for page := 1; page <= 3; page++ {
			out, err := e.app.dispatchTool(t.Context(), e.bot, "read_issue", map[string]any{
				"repo": "acme/widgets", "number": float64(7), "page": float64(page),
			})
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Comments []struct {
					Body string `json:"body"`
				} `json:"comments"`
				Next  int  `json:"next_page"`
				Trunc bool `json:"truncated"`
			}
			if json.Unmarshal([]byte(out), &parsed) != nil {
				t.Fatal(out)
			}
			for _, c := range parsed.Comments {
				got = append(got, c.Body)
			}
			if page < 3 && (!parsed.Trunc || parsed.Next != page+1) {
				t.Fatalf("page %d next %d trunc %v", page, parsed.Next, parsed.Trunc)
			}
			if page == 3 && (parsed.Trunc || parsed.Next != 0) {
				t.Fatalf("last page trunc %v next %d", parsed.Trunc, parsed.Next)
			}
		}
		if len(got) != 25 {
			t.Fatalf("count %d", len(got))
		}
		for i, body := range got {
			want := "c" + strconv.Itoa(i+1)
			if body != want {
				t.Fatalf("gap at %d got %s", i, body)
			}
		}
	})

	t.Run("patch offset walks the whole diff", func(t *testing.T) {
		mode.Store("patch")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7),
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, `\u003c`) {
			t.Fatal("html escaped")
		}
		var first struct {
			Files []struct {
				Patch string `json:"patch"`
				Next  int    `json:"patch_next"`
				Total int    `json:"patch_total"`
			} `json:"files"`
			Next int `json:"next_offset"`
		}
		if json.Unmarshal([]byte(out), &first) != nil || len(first.Files) != 1 {
			t.Fatal(out)
		}
		if first.Files[0].Total != len(longPatch) || first.Next == 0 || !utf8.ValidString(first.Files[0].Patch) {
			t.Fatalf("window %+v", first.Files[0])
		}
		out, err = e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "offset": float64(first.Next),
		})
		if err != nil {
			t.Fatal(err)
		}
		var second struct {
			Files []struct {
				Patch string `json:"patch"`
			} `json:"files"`
			Next int `json:"next_offset"`
		}
		if json.Unmarshal([]byte(out), &second) != nil || len(second.Files) != 1 || second.Next != 0 {
			t.Fatal(out)
		}
		if first.Files[0].Patch+second.Files[0].Patch != longPatch || !utf8.ValidString(second.Files[0].Patch) {
			t.Fatalf("gap or overlap %q + %q", first.Files[0].Patch, second.Files[0].Patch)
		}
	})

	t.Run("angle brackets stay raw", func(t *testing.T) {
		mode.Store("angle")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil || !strings.Contains(out, "a <tag> & more") || strings.Contains(out, `\u003c`) || !strings.HasPrefix(out, `{"untrusted_github_data_notice":`) {
			t.Fatalf("%v %s", err, out)
		}
	})

	t.Run("legacy status stays beside check runs", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"name":"build"`, `"name":"lint"`, `"conclusion":"in_progress"`, "ci/legacy-required", `"combined_state":"failure"`, `"source":"status"`, `"body":"c1"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %s in %s", want, out)
			}
		}
	})

	t.Run("check runs use the requested page", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "page": float64(2),
		})
		if err != nil || !strings.Contains(out, "lint-page-2") || strings.Contains(out, `"name":"build"`) {
			t.Fatalf("%v %s", err, out)
		}
	})

	t.Run("full file page is truncated", func(t *testing.T) {
		mode.Store("manyfiles")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{"repo": "acme/widgets", "number": float64(7)})
		if err != nil || !strings.Contains(out, `"truncated":true`) || !strings.Contains(out, `"next_page":2`) || strings.Contains(out, "f25.go") {
			t.Fatalf("%v %s", err, out)
		}
	})

	t.Run("token in a title is redacted", func(t *testing.T) {
		mode.Store("token")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets"})
		if err != nil || strings.Contains(out, leak) || !strings.Contains(out, "[redacted]") {
			t.Fatalf("%v %s", err, out)
		}
	})

	t.Run("missing grant does no http", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, []string{"git"})
		before := hits.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{"repo": "acme/widgets", "title": "X"})
		if err == nil || !strings.Contains(err.Error(), "github grant required") || hits.Load() != before || e.evals.Load() != 0 {
			t.Fatalf("%v hits %d", err, hits.Load()-before)
		}
	})

	t.Run("blank comment never asks", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		before := hits.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "  \n",
		})
		if err == nil || !strings.Contains(err.Error(), "invalid arguments") || hits.Load() != before || e.evals.Load() != 0 {
			t.Fatalf("%v hits %d evals %d", err, hits.Load()-before, e.evals.Load())
		}
	})

	t.Run("revoked grant writes nothing", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		before := posts.Load()
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{"repo": "acme/widgets", "title": "Later"})
			errCh <- err
		}()
		_ = waitCardArgs(t, e.app, e.bot.ID, "create_issue")
		res, b := do(t, "PATCH", e.url+"/api/bots/"+e.bot.ID, map[string]any{"grants": []string{}}, "")
		if res.StatusCode != 200 {
			t.Fatalf("patch %d %s", res.StatusCode, b)
		}
		decideCard(t, e.app, e.bot.ID, "create_issue")
		err := <-errCh
		if err == nil || !strings.Contains(err.Error(), "github grant required") || posts.Load() != before {
			t.Fatalf("%v posts %d", err, posts.Load()-before)
		}
	})

	t.Run("revoked allowlist writes nothing", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		before := posts.Load()
		end := e.app.holdTurn(e.bot.ID)
		defer end()
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
				"repo": "acme/widgets", "number": float64(7), "body": "later",
			})
			errCh <- err
		}()
		_ = waitCardArgs(t, e.app, e.bot.ID, "create_comment")
		e.app.editPol(func(p *policy.Policy) { p.GitHub.Repos = nil })
		decideCard(t, e.app, e.bot.ID, "create_comment")
		err := <-errCh
		if err == nil || !strings.Contains(err.Error(), "not allowlisted") || posts.Load() != before {
			t.Fatalf("%v posts %d", err, posts.Load()-before)
		}
	})

	t.Run("unverified create is not a denial", func(t *testing.T) {
		mode.Store("html")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		before := posts.Load()
		done := approveCard(e.app, e.bot.ID, "create_issue")
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{"repo": "acme/widgets", "title": "Maybe"})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || !strings.Contains(out, "may have been created, check before retrying") || posts.Load() != before+1 {
			t.Fatalf("%v posts %d %s", err, posts.Load()-before, out)
		}
		raw := readAudit(t, e.audit)
		if !strings.Contains(raw, `"decision":"unknown"`) || !strings.Contains(raw, "sent (response unverified)") || strings.Contains(raw, "<html>") {
			t.Fatalf("audit %s", raw)
		}
	})

	t.Run("status 500 stays a denial", func(t *testing.T) {
		mode.Store("boom")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		done := approveCard(e.app, e.bot.ID, "create_issue")
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{"repo": "acme/widgets", "title": "Nope"})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err == nil || !strings.Contains(err.Error(), "github status 500") {
			t.Fatal(err)
		}
		raw := readAudit(t, e.audit)
		if !strings.Contains(raw, `"decision":"deny"`) || strings.Contains(raw, `"decision":"unknown"`) {
			t.Fatalf("audit %s", raw)
		}
	})

	t.Run("bad comment url is unverified", func(t *testing.T) {
		mode.Store("badurl")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		done := approveCard(e.app, e.bot.ID, "create_comment")
		out, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "hello",
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil || strings.Contains(out, "other/widgets") || !strings.Contains(out, "may have been created") {
			t.Fatalf("%v %s", err, out)
		}
	})

	t.Run("closed audit sink refuses the post", func(t *testing.T) {
		mode.Store("ok")
		for _, tool := range []string{"create_issue", "create_pr"} {
			t.Run(tool, func(t *testing.T) {
				e := newEnv(t, nil)
				e.app.perm.AddHook(func(req permission.Request) permission.HookResult {
					if req.Tool == tool {
						_ = e.lg.Close()
					}
					return permission.HookResult{}
				})
				before := posts.Load()
				done := approveCard(e.app, e.bot.ID, tool)
				args := map[string]any{"repo": "acme/widgets", "title": "Audited"}
				if tool == "create_pr" {
					args["head"] = "feature"
					args["base"] = "main"
				}
				_, err := e.app.dispatchTool(t.Context(), e.bot, tool, args)
				if aerr := <-done; aerr != nil {
					t.Fatal(aerr)
				}
				if err == nil || !strings.Contains(err.Error(), "audit log unavailable") || posts.Load() != before {
					t.Fatalf("%v posts %d", err, posts.Load()-before)
				}
			})
		}
	})

	t.Run("missing target does not ask", func(t *testing.T) {
		mode.Store("missing")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		before := posts.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "body": "hello",
		})
		if err == nil || e.evals.Load() != 0 || posts.Load() != before {
			t.Fatalf("%v evals %d posts %d", err, e.evals.Load(), posts.Load()-before)
		}
	})

	t.Run("audit row names the write", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		body := "the list is blank"
		done := approveCard(e.app, e.bot.ID, "create_issue")
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Empty state", "body": body,
		})
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		if err != nil {
			t.Fatal(err)
		}
		raw := readAudit(t, e.audit)
		sum := sha256.Sum256([]byte(body))
		wantHash := `"body_sha256":"` + hex.EncodeToString(sum[:]) + `"`
		wantLen := `"body_len":` + strconv.Itoa(len(body))
		sawIntent := false
		sawSent := false
		for _, line := range strings.Split(raw, "\n") {
			if !strings.Contains(line, "github_issue_intent") && !strings.Contains(line, "github_issue_allowed") {
				continue
			}
			if strings.Contains(line, body) {
				t.Fatalf("audit copied the body: %s", line)
			}
			if strings.Contains(line, "github_issue_intent") && strings.Contains(line, wantHash) && strings.Contains(line, wantLen) {
				sawIntent = true
			}
			if strings.Contains(line, "github_issue_allowed") && strings.Contains(line, "https://github.com/acme/widgets/issues/4") && strings.Contains(line, `"number":`) {
				sawSent = true
			}
		}
		if !sawIntent || !sawSent {
			t.Fatalf("audit %s", raw)
		}
	})

	t.Run("jail socket hides issue routes", func(t *testing.T) {
		e := newEnv(t, nil)
		px, err := e.app.openGitHubProxy(e.app.freshBot(e.bot))
		if err != nil || px == nil {
			t.Fatalf("proxy %v %v", px, err)
		}
		t.Cleanup(func() { _ = px.Close() })
		client := &http.Client{Transport: &http.Transport{
			Dial: func(string, string) (net.Conn, error) {
				return net.Dial("unix", px.Sock())
			},
		}}
		get := func(path string) int {
			t.Helper()
			req, err := http.NewRequest(http.MethodGet, "http://proxy"+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			return res.StatusCode
		}
		if got := get("/api/repos/acme/widgets/issues?state=open&per_page=10&page=1"); got != http.StatusForbidden {
			t.Fatalf("issues %d", got)
		}
		if got := get("/api/repos/acme/widgets/pulls/7"); got != http.StatusForbidden {
			t.Fatalf("pull %d", got)
		}
		if got := get("/api/repos/acme/widgets"); got == http.StatusForbidden {
			t.Fatal("repo root refused")
		}
	})

	t.Run("bad page does no http", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		before := hits.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "list_issues", map[string]any{"repo": "acme/widgets", "page": float64(21)})
		if err == nil || !strings.Contains(err.Error(), "invalid arguments") || hits.Load() != before {
			t.Fatalf("%v hits %d", err, hits.Load()-before)
		}
	})

	t.Run("hidden text", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		e.app.editPol(func(p *policy.Policy) { p.PromptTimeout = 200 * time.Millisecond })
		classes := []struct{ name, sample string }{
			{"bidi", "\u202E"},
			{"zero-width", "\u200B"},
			{"tag", "\U000E0053"},
			{"c1", "\u0085"},
			{"format", "\u2061"},
			{"variation", "\uFE0F"},
		}
		type call struct {
			tool string
			args map[string]any
		}
		for _, c := range classes {
			for _, where := range []string{"body", "title"} {
				t.Run(where+"/"+c.name, func(t *testing.T) {
					calls := []call{
						{"create_issue", map[string]any{"repo": "acme/widgets", "title": "Fine", "body": "Fine"}},
						{"create_pr", map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Fine", "body": "Fine"}},
					}
					if where == "body" {
						calls = append(calls, call{"create_comment", map[string]any{"repo": "acme/widgets", "number": float64(7), "body": "Fine"}})
					}
					for i := range calls {
						if where == "title" {
							calls[i].args["title"] = "Fine" + c.sample
						} else {
							calls[i].args["body"] = "Fine" + c.sample
						}
					}
					beforeHits := hits.Load()
					beforeEvals := e.evals.Load()
					beforePosts := posts.Load()
					for _, tc := range calls {
						_, err := e.app.dispatchTool(t.Context(), e.bot, tc.tool, tc.args)
						if err == nil || !strings.Contains(err.Error(), "text is not allowed") {
							t.Fatalf("%s %v", tc.tool, err)
						}
					}
					if e.evals.Load() != beforeEvals || posts.Load() != beforePosts || hits.Load() != beforeHits {
						t.Fatalf("evals %d posts %d hits %d", e.evals.Load()-beforeEvals, posts.Load()-beforePosts, hits.Load()-beforeHits)
					}
				})
			}
		}
	})

	t.Run("too many lines", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		e.app.editPol(func(p *policy.Policy) { p.PromptTimeout = 200 * time.Millisecond })
		body := strings.Repeat("a\n", 400)
		before := e.evals.Load()
		_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
			"repo": "acme/widgets", "title": "Fine", "body": body,
		})
		if err == nil || !strings.Contains(err.Error(), "too many lines") || e.evals.Load() != before {
			t.Fatalf("%v evals %d", err, e.evals.Load()-before)
		}
	})

	t.Run("crlf is stored as lf", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		before := posts.Load()
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
				"repo": "acme/widgets", "title": "Fine", "body": "a\r\nb",
			})
			errCh <- err
		}()
		card := waitCardArgs(t, e.app, e.bot.ID, "create_issue")
		if bodyOf(t, card) != "a\nb" {
			t.Fatalf("card %q", bodyOf(t, card))
		}
		decideCard(t, e.app, e.bot.ID, "create_issue")
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		posted, _ := lastPost.Load().(string)
		if posts.Load() != before+1 || !strings.Contains(posted, `"body":"a\nb"`) || strings.Contains(posted, "\r") {
			t.Fatalf("posted %s", posted)
		}
	})

	t.Run("target title is escaped", func(t *testing.T) {
		mode.Store("rtl-title")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
				"repo": "acme/widgets", "number": float64(7), "body": "hello",
			})
			errCh <- err
		}()
		card := waitCardArgs(t, e.app, e.bot.ID, "create_comment")
		title, _ := card["target_title"].(string)
		if title != "ab⟦U+202E⟧cd" || strings.ContainsRune(title, '\u202E') {
			t.Fatalf("title %q", title)
		}
		decideCard(t, e.app, e.bot.ID, "create_comment")
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("long target title is marked", func(t *testing.T) {
		mode.Store("long-title")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_comment", map[string]any{
				"repo": "acme/widgets", "number": float64(7), "body": "hello",
			})
			errCh <- err
		}()
		card := waitCardArgs(t, e.app, e.bot.ID, "create_comment")
		title, _ := card["target_title"].(string)
		if len(title) != 2000 || card["target_title_clipped"] != true {
			t.Fatalf("len %d clipped %v", len(title), card["target_title_clipped"])
		}
		decideCard(t, e.app, e.bot.ID, "create_comment")
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("secret and links stay on the card", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		body := "see https://user-images.githubusercontent.com/1/x.png and https://github.com/acme/widgets and ghp_example"
		errCh := make(chan error, 1)
		go func() {
			_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
				"repo": "acme/widgets", "title": "Fine", "body": body,
			})
			errCh <- err
		}()
		card := waitCardArgs(t, e.app, e.bot.ID, "create_issue")
		if card["secret_warning"] != true || bodyOf(t, card) != body {
			t.Fatalf("card %#v", card)
		}
		links, _ := card["links"].([]any)
		joined := fmt.Sprint(links)
		if !strings.Contains(joined, "https://user-images.githubusercontent.com/1/x.png") || strings.Contains(joined, "https://github.com/acme/widgets") {
			t.Fatalf("links %v", links)
		}
		decideCard(t, e.app, e.bot.ID, "create_issue")
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("closed audit does not ask", func(t *testing.T) {
		mode.Store("ok")
		e := newEnv(t, nil)
		e.app.editPol(func(p *policy.Policy) { p.PromptTimeout = 200 * time.Millisecond })
		if err := e.lg.Close(); err != nil {
			t.Fatal(err)
		}
		before := e.evals.Load()
		for _, tc := range []struct {
			tool string
			args map[string]any
		}{
			{"create_issue", map[string]any{"repo": "acme/widgets", "title": "Fine"}},
			{"create_comment", map[string]any{"repo": "acme/widgets", "number": float64(7), "body": "hello"}},
			{"create_pr", map[string]any{"repo": "acme/widgets", "head": "feature", "base": "main", "title": "Fine"}},
		} {
			_, err := e.app.dispatchTool(t.Context(), e.bot, tc.tool, tc.args)
			if err == nil || !strings.Contains(err.Error(), "audit log unavailable") {
				t.Fatalf("%s %v", tc.tool, err)
			}
		}
		if e.evals.Load() != before {
			t.Fatalf("evals %d", e.evals.Load()-before)
		}
	})

	t.Run("disabled audit does not ask", func(t *testing.T) {
		mode.Store("ok")
		for _, name := range []string{"empty", "nil"} {
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, nil)
				e.app.editPol(func(p *policy.Policy) { p.PromptTimeout = 200 * time.Millisecond })
				if name == "nil" {
					e.app.audit = nil
				} else {
					e.app.audit = &audit.Logger{}
				}
				before := e.evals.Load()
				_, err := e.app.dispatchTool(t.Context(), e.bot, "create_issue", map[string]any{
					"repo": "acme/widgets", "title": "Fine",
				})
				if err == nil || !strings.Contains(err.Error(), "audit log unavailable") || e.evals.Load() != before {
					t.Fatalf("%v evals %d", err, e.evals.Load()-before)
				}
			})
		}
	})

	t.Run("read issue points at a pull", func(t *testing.T) {
		mode.Store("pull-url")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		_, err := e.app.dispatchTool(t.Context(), e.bot, "read_issue", map[string]any{
			"repo": "acme/widgets", "number": float64(7),
		})
		if err == nil || !strings.Contains(err.Error(), "pull request") || strings.Contains(err.Error(), "moved") {
			t.Fatal(err)
		}
	})

	t.Run("escape heavy page keeps checks", func(t *testing.T) {
		mode.Store("heavy")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7),
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, `"omitted":true`) || !strings.Contains(out, "check-keep") || !strings.Contains(out, `"combined_state":"success"`) || !strings.Contains(out, `\u0001`) || len(out) > githubSizeCapBytes {
			t.Fatalf("len %d heavy page dropped a field", len(out))
		}
	})

	t.Run("escape heavy page names a continuation", func(t *testing.T) {
		mode.Store("heavy")
		t.Cleanup(func() { mode.Store("ok") })
		e := newEnv(t, nil)
		out, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7),
		})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if json.Unmarshal([]byte(out), &got) != nil {
			t.Fatalf("json %s", out[:min(80, len(out))])
		}
		next, _ := got["next_offset"].(float64)
		if next <= 0 || strings.Contains(out, `"omitted":true`) {
			t.Fatalf("next %v", next)
		}
		again, err := e.app.dispatchTool(t.Context(), e.bot, "read_pr", map[string]any{
			"repo": "acme/widgets", "number": float64(7), "offset": next,
		})
		if err != nil || strings.Contains(again, `"omitted":true`) || !strings.Contains(again, "check-keep") {
			t.Fatalf("%v %s", err, again)
		}
	})
}

func waitCardArgs(t *testing.T, app *App, botID, tool string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, card := range app.perm.Pending(botID) {
			if card["tool"] != tool {
				continue
			}
			args, _ := card["arguments"].(map[string]any)
			out := map[string]any{}
			for k, v := range args {
				out[k] = v
			}
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s card", tool)
	return nil
}

func decideCard(t *testing.T, app *App, botID, tool string) {
	t.Helper()
	for _, card := range app.perm.Pending(botID) {
		if card["tool"] != tool {
			continue
		}
		id, _ := card["id"].(string)
		runID, _ := card["run_id"].(string)
		if err := app.perm.DecideFor(botID, runID, id, permission.AllowOnce); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("card gone")
}

func writeR2Comments(w http.ResponseWriter, page, per int) {
	if per < 1 {
		per = 10
	}
	start := (page-1)*per + 1
	io.WriteString(w, "[")
	n := 0
	for id := start; id <= 25 && n < per; id++ {
		if n > 0 {
			io.WriteString(w, ",")
		}
		idText := strconv.Itoa(id)
		io.WriteString(w, `{"id":`+idText+`,"body":"c`+idText+`","html_url":"https://github.com/acme/widgets/issues/7#issuecomment-`+idText+`","user":{"login":"bea"}}`)
		n++
	}
	io.WriteString(w, "]")
}

func writeR2Files(w http.ResponseWriter, page, per int) {
	if per < 1 {
		per = 10
	}
	start := (page-1)*per + 1
	io.WriteString(w, "[")
	n := 0
	for i := start; i <= 25 && n < per; i++ {
		if n > 0 {
			io.WriteString(w, ",")
		}
		io.WriteString(w, `{"filename":"f`+strconv.Itoa(i)+`.go","status":"modified","additions":1,"deletions":0,"patch":"p"}`)
		n++
	}
	io.WriteString(w, "]")
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func writeHeavyPage(w http.ResponseWriter, path, sha string) bool {
	fill := strings.Repeat("\x01", 4096)
	enc := json.NewEncoder(w)
	switch path {
	case "/repos/acme/widgets/pulls/7":
		return enc.Encode(map[string]any{
			"html_url": "https://github.com/acme/widgets/pull/7",
			"title":    "Heavy",
			"body":     fill,
			"state":    "open",
			"head":     map[string]any{"ref": "feature", "sha": sha},
			"base":     map[string]any{"ref": "main"},
		}) == nil
	case "/repos/acme/widgets/pulls/7/files":
		files := make([]map[string]any, 9)
		for i := range files {
			files[i] = map[string]any{"filename": fmt.Sprintf("f%d.go", i), "status": "modified", "additions": 1, "deletions": 0, "patch": fill}
		}
		return enc.Encode(files) == nil
	case "/repos/acme/widgets/pulls/7/reviews":
		rows := make([]map[string]any, 9)
		for i := range rows {
			rows[i] = map[string]any{"user": map[string]any{"login": "bea"}, "state": "COMMENTED", "body": fill}
		}
		return enc.Encode(rows) == nil
	case "/repos/acme/widgets/pulls/7/comments":
		rows := make([]map[string]any, 9)
		for i := range rows {
			rows[i] = map[string]any{"user": map[string]any{"login": "bea"}, "path": "a.go", "line": 1, "body": fill, "diff_hunk": fill}
		}
		return enc.Encode(rows) == nil
	case "/repos/acme/widgets/issues/7/comments":
		rows := make([]map[string]any, 9)
		for i := range rows {
			id := i + 1
			rows[i] = map[string]any{
				"id": id, "body": fill,
				"html_url": fmt.Sprintf("https://github.com/acme/widgets/issues/7#issuecomment-%d", id),
				"user":     map[string]any{"login": "bea"},
			}
		}
		return enc.Encode(rows) == nil
	}
	if strings.HasSuffix(path, "/check-runs") {
		return enc.Encode(map[string]any{
			"total_count": 1,
			"check_runs": []map[string]any{{
				"name": "check-keep", "status": "completed", "conclusion": "success",
			}},
		}) == nil
	}
	if strings.HasSuffix(path, "/status") {
		return enc.Encode(map[string]any{
			"state":    "success",
			"statuses": []map[string]any{{"context": "legacy-keep", "state": "success"}},
		}) == nil
	}
	return false
}
