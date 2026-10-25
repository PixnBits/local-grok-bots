package github

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func pktLine(payload string) string {
	return fmt.Sprintf("%04x%s", len(payload)+4, payload)
}

func oneRef(old, new, ref string) string {
	return pktLine(old+" "+new+" "+ref+"\n") + "0000"
}

func oid(ch byte) string {
	return strings.Repeat(string(ch), 40)
}

func TestWriteWindowAndRefUpdates(t *testing.T) {
	var mu sync.Mutex
	var hits int
	var sawBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		b, _ := io.ReadAll(r.Body)
		sawBody = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()

	pushWin := Window{Kind: WindowPush, Owner: "Acme", Repo: "Widgets", Branch: "feature", Default: "main", Old: oid('0')}
	prWin := Window{Kind: WindowPR, Owner: "Acme", Repo: "Widgets", Branch: "feature", Base: "main"}
	approved := oneRef(oid('0'), oid('a'), "refs/heads/feature")
	approvedCaps := pktLine(oid('0')+" "+oid('b')+" refs/heads/feature\x00report-status side-band-64k\n") + "0000PACK-bytes"

	type hit struct {
		access Access
		win    Window
		method string
		path   string
		body   string
		code   int
		reason string
		fwd    bool
	}
	cases := []hit{
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", approved, http.StatusNoContent, "", true},
		{AccessWrite, pushWin, http.MethodPost, "/github/Acme/Widgets.git/git-receive-pack", approvedCaps, http.StatusNoContent, "", true},
		{AccessWrite, pushWin, http.MethodGet, "/github/acme/widgets.git/info/refs?service=git-receive-pack", "", http.StatusNoContent, "", true},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('a'), oid('0'), "refs/heads/feature"), http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('b'), oid('a'), "refs/heads/feature"), http.StatusForbidden, "ref", false},
		{AccessWrite, Window{Kind: WindowPush, Owner: "acme", Repo: "widgets", Branch: "feature", Default: "main", Old: oid('c')}, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('c'), oid('a'), "refs/heads/feature"), http.StatusNoContent, "", true},
		{AccessWrite, Window{Kind: WindowPush, Owner: "acme", Repo: "widgets", Branch: "feature", Default: "main"}, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", approved, http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('0'), strings.Repeat("0", 64), "refs/heads/feature"), http.StatusForbidden, "ref", false},
		{AccessWrite, Window{Kind: WindowPush, Owner: "acme", Repo: "widgets", Branch: "Feature", Default: "feature"}, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('0'), oid('a'), "refs/heads/Feature"), http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('0'), oid('a'), "refs/tags/v1"), http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", oneRef(oid('0'), oid('a'), "refs/heads/other"), http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", pktLine(oid('0')+" "+oid('a')+" refs/heads/feature\n") + pktLine(oid('0')+" "+oid('b')+" refs/heads/other\n") + "0000", http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", "0000", http.StatusForbidden, "ref", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/other/widgets.git/git-receive-pack", approved, http.StatusForbidden, "", false},
		{AccessWrite, pushWin, http.MethodPost, "/github/acme/widgets.git/git-upload-pack", approved, http.StatusForbidden, "", false},
		{AccessWrite, pushWin, http.MethodGet, "/github/acme/widgets.git/info/refs?service=git-upload-pack", "", http.StatusForbidden, "", false},
		{AccessWrite, pushWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"head":"feature"}`, http.StatusForbidden, "", false},
		{AccessWrite, Window{}, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", approved, http.StatusForbidden, "", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"title":"T","head":"feature","base":"main"}`, http.StatusNoContent, "", true},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/Acme/Widgets/pulls", `{"head":"other","base":"main"}`, http.StatusForbidden, "head", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"head":"evil","HEAD":"feat","base":"main"}`, http.StatusForbidden, "head", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"hEaD":"feature","base":"main"}`, http.StatusForbidden, "head", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"head":"feature","head":"evil","base":"main"}`, http.StatusForbidden, "head", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"head":"feature","base":"other"}`, http.StatusForbidden, "base", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/pulls", `{"title":"T","head":"feature","base":"main","body":"b","draft":false}`, http.StatusNoContent, "", true},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/other/pulls", `{"head":"feature"}`, http.StatusForbidden, "", false},
		{AccessWrite, prWin, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", approved, http.StatusForbidden, "", false},
		{AccessWrite, prWin, http.MethodGet, "/api/repos/acme/widgets", "", http.StatusForbidden, "", false},
		{AccessWrite, prWin, http.MethodPost, "/api/repos/acme/widgets/merges", `{"head":"feature"}`, http.StatusForbidden, "", false},
		{AccessRead, Window{}, http.MethodPost, "/github/acme/widgets.git/git-upload-pack", "0000", http.StatusNoContent, "", true},
		{AccessRead, Window{}, http.MethodPost, "/github/acme/widgets.git/git-receive-pack", approved, http.StatusForbidden, "", false},
	}
	for i, tc := range cases {
		var audits []Audit
		repos := []string{"acme/widgets", "acme/other", "other/widgets"}
		p, err := New(Config{
			Repos:   repos,
			Token:   func() (string, error) { return tokenSecret, nil },
			GitBase: up.URL,
			APIBase: up.URL,
			Access:  tc.access,
			Window:  tc.win,
			Audit:   func(a Audit) { audits = append(audits, a) },
		})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(p)
		mu.Lock()
		before := hits
		mu.Unlock()
		req, err := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := io.ReadAll(res.Body)
		res.Body.Close()
		srv.Close()
		if res.StatusCode != tc.code {
			t.Fatalf("case %d %s %s -> %d body %q, want %d", i, tc.method, tc.path, res.StatusCode, resp, tc.code)
		}
		if strings.Contains(string(resp), tokenSecret) {
			t.Fatalf("case %d leaked token", i)
		}
		mu.Lock()
		gotHits := hits - before
		body := sawBody
		mu.Unlock()
		if tc.fwd && gotHits != 1 {
			t.Fatalf("case %d hits %d", i, gotHits)
		}
		if !tc.fwd && gotHits != 0 {
			t.Fatalf("case %d forwarded", i)
		}
		if tc.fwd && tc.body != "" && !strings.Contains(body, "refs/heads/feature") && !strings.Contains(body, `"head":"feature"`) && !strings.HasPrefix(tc.path, "/github/") {
			t.Fatalf("case %d body %q", i, body)
		}
		if tc.reason != "" {
			if len(audits) != 1 || audits[0].Reason != tc.reason {
				t.Fatalf("case %d audit %#v", i, audits)
			}
		}
		if strings.Contains(tc.path, "git-upload-pack") && len(audits) == 1 && audits[0].Action == "github_write" {
			t.Fatalf("case %d upload-pack labelled write", i)
		}
	}
}
