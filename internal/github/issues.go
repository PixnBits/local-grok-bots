package github

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Limits bounds one paged GitHub read. The caller sets every field.
// PerPage is 1..100 because that is the query the proxy forwards.
// Page is the first page to request. Zero means page 1.
// MaxPages is how many pages this call may request, starting at Page.
type Limits struct {
	PerPage  int
	MaxItems int
	MaxPages int
	Page     int
}

func (l Limits) ok() bool {
	return l.PerPage >= 1 && l.PerPage <= 100 && l.MaxItems >= 1 && l.MaxPages >= 1
}

func (l Limits) startPage() int {
	if l.Page < 1 {
		return 1
	}
	return l.Page
}

// Issue is one open issue. Pull requests are not included.
type Issue struct {
	Number int
	Title  string
	State  string
	Body   string
	URL    string
	User   string
}

// IssueComment is one conversation comment on an issue or a pull request.
type IssueComment struct {
	ID   int
	User string
	Body string
	URL  string
}

// PullFile is one changed file. Patch is the diff GitHub returned, if any.
type PullFile struct {
	Name      string
	Status    string
	Additions int
	Deletions int
	Patch     string
}

// PullReview is one review summary.
type PullReview struct {
	User  string
	State string
	Body  string
}

// ReviewComment is one inline review comment.
type ReviewComment struct {
	User     string
	Path     string
	Line     int
	Body     string
	DiffHunk string
}

// Check is one check run or commit status conclusion.
// Source is check_run or status.
type Check struct {
	Name       string
	Conclusion string
	Source     string
}

// PullDetail is what read_pr shows the model.
type PullDetail struct {
	URL           string
	Title         string
	Body          string
	State         string
	Head          string
	Base          string
	Files         []PullFile
	Reviews       []PullReview
	Comments      []ReviewComment
	Checks        []Check
	Statuses      []Check
	CombinedState string
	Conversation  []IssueComment
	Truncated     bool
}

// IssueTarget is the issue or pull request a comment would be attached to.
type IssueTarget struct {
	Kind  string
	Title string
	State string
	URL   string
}

// CreatedIssue is the projection of a created issue.
type CreatedIssue struct {
	URL    string
	Number int
}

// CreatedComment is the projection of a created comment.
type CreatedComment struct {
	URL string
	ID  int
}

// NewIssue is an issue the daemon is allowed to send.
type NewIssue struct {
	Title string
	Body  string
}

// ValidIssueTitle reports whether title can be sent as an issue title.
func ValidIssueTitle(s string) bool { return ValidPullTitle(s) }

// ValidIssueBody reports whether body can be sent. Empty is allowed.
func ValidIssueBody(s string) bool { return ValidPullBody(s) }

// ValidCommentBody reports whether a comment body can be sent.
func ValidCommentBody(s string) bool {
	return textIssue(s, "comment") == ""
}

// AcceptIssueURL accepts https://github.com/owner/repo/issues/N for this repo.
// The returned URL is rebuilt. The raw string is not passed through.
func AcceptIssueURL(owner, repo, raw string) (string, int, bool) {
	n, ok := acceptNumberURL(owner, repo, raw, "issues")
	if !ok {
		return "", 0, false
	}
	return "https://github.com/" + owner + "/" + repo + "/issues/" + strconv.Itoa(n), n, true
}

// AcceptCommentURL accepts an issue or pull comment URL for this number.
// The fragment must be issuecomment-<id>. The returned URL is rebuilt.
func AcceptCommentURL(owner, repo string, number, id int, raw string) (string, bool) {
	if number < 1 || id < 1 || strings.ContainsAny(raw, "\r\n\t\x00 ") || len(raw) > 300 {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return "", false
	}
	if u.RawQuery != "" {
		return "", false
	}
	frag := u.Fragment
	if !strings.HasPrefix(frag, "issuecomment-") {
		return "", false
	}
	gotID, err := strconv.Atoi(strings.TrimPrefix(frag, "issuecomment-"))
	if err != nil || gotID != id || strconv.Itoa(gotID) != strings.TrimPrefix(frag, "issuecomment-") {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 4 {
		return "", false
	}
	if !strings.EqualFold(parts[0], owner) || !strings.EqualFold(parts[1], repo) {
		return "", false
	}
	kind := parts[2]
	if kind != "issues" && kind != "pull" {
		return "", false
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n != number || strconv.Itoa(n) != parts[3] {
		return "", false
	}
	return "https://github.com/" + owner + "/" + repo + "/" + kind + "/" + parts[3] + "#issuecomment-" + strconv.Itoa(id), true
}

func acceptNumberURL(owner, repo, raw, kind string) (int, bool) {
	if strings.ContainsAny(raw, "\r\n\t\x00 ") || len(raw) > 300 {
		return 0, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return 0, false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return 0, false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[2] != kind {
		return 0, false
	}
	if !strings.EqualFold(parts[0], owner) || !strings.EqualFold(parts[1], repo) {
		return 0, false
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n < 1 || strconv.Itoa(n) != parts[3] {
		return 0, false
	}
	return n, true
}

// ListOpenIssues pages open issues until the limit. Pull requests are skipped.
// truncated is true when the item cap or the page cap stopped the read.
func ListOpenIssues(ctx context.Context, client *http.Client, base, owner, repo string, lim Limits) ([]Issue, bool, error) {
	if !lim.ok() {
		return nil, false, &APIError{kind: "transport"}
	}
	var out []Issue
	truncated := false
	pageTrunc, err := forPages(ctx, client, lim, func(page int) (string, error) {
		return apiURL(base, owner, repo, "/issues", pageQuery(page, lim.PerPage, true))
	}, func(batch []json.RawMessage) (bool, error) {
		for _, raw := range batch {
			var wire struct {
				Number      int                    `json:"number"`
				Title       string                 `json:"title"`
				State       string                 `json:"state"`
				Body        string                 `json:"body"`
				HTMLURL     string                 `json:"html_url"`
				User        struct{ Login string } `json:"user"`
				PullRequest json.RawMessage        `json:"pull_request"`
			}
			if json.Unmarshal(raw, &wire) != nil || wire.Number < 1 {
				return false, &APIError{kind: "response"}
			}
			if len(wire.PullRequest) > 0 && string(wire.PullRequest) != "null" {
				continue
			}
			if wire.State != "open" {
				continue
			}
			got, n, ok := AcceptIssueURL(owner, repo, wire.HTMLURL)
			if !ok || n != wire.Number {
				return false, urlMiss(wire.HTMLURL)
			}
			if len(out) >= lim.MaxItems {
				truncated = true
				return true, nil
			}
			out = append(out, Issue{
				Number: wire.Number,
				Title:  wire.Title,
				State:  wire.State,
				Body:   wire.Body,
				URL:    got,
				User:   safeLogin(wire.User.Login),
			})
		}
		if len(out) >= lim.MaxItems {
			truncated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []Issue{}
	}
	return out, truncated || pageTrunc, nil
}

// GetIssue reads one issue.
func GetIssue(ctx context.Context, client *http.Client, base, owner, repo string, number int) (Issue, error) {
	rawURL, err := apiURL(base, owner, repo, "/issues/"+strconv.Itoa(number), "")
	if err != nil || number < 1 {
		return Issue{}, &APIError{kind: "transport"}
	}
	buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
	if err != nil {
		return Issue{}, err
	}
	var wire struct {
		Number  int                    `json:"number"`
		Title   string                 `json:"title"`
		State   string                 `json:"state"`
		Body    string                 `json:"body"`
		HTMLURL string                 `json:"html_url"`
		User    struct{ Login string } `json:"user"`
	}
	if json.Unmarshal(buf, &wire) != nil || wire.Number != number {
		return Issue{}, &APIError{kind: "response"}
	}
	if wire.State != "open" && wire.State != "closed" {
		return Issue{}, &APIError{kind: "response"}
	}
	got, n, ok := AcceptIssueURL(owner, repo, wire.HTMLURL)
	if ok && n == number {
		return Issue{
			Number: number, Title: wire.Title, State: wire.State, Body: wire.Body, URL: got, User: safeLogin(wire.User.Login),
		}, nil
	}
	if pull, pok := AcceptPullURL(owner, repo, wire.HTMLURL); pok && urlNumber(pull) == number {
		return Issue{}, &APIError{kind: "pull"}
	}
	return Issue{}, urlMiss(wire.HTMLURL)
}

func urlNumber(raw string) int {
	i := strings.LastIndex(raw, "/")
	if i < 0 || i+1 >= len(raw) {
		return 0
	}
	n, err := strconv.Atoi(raw[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// ListIssueComments pages conversation comments on an issue or pull request.
func ListIssueComments(ctx context.Context, client *http.Client, base, owner, repo string, number int, lim Limits) ([]IssueComment, bool, error) {
	if !lim.ok() || number < 1 {
		return nil, false, &APIError{kind: "transport"}
	}
	var out []IssueComment
	truncated := false
	pageTrunc, err := forPages(ctx, client, lim, func(page int) (string, error) {
		return apiURL(base, owner, repo, "/issues/"+strconv.Itoa(number)+"/comments", pageQuery(page, lim.PerPage, false))
	}, func(batch []json.RawMessage) (bool, error) {
		for _, raw := range batch {
			item, err := projectComment(owner, repo, number, raw)
			if err != nil {
				return false, err
			}
			if len(out) >= lim.MaxItems {
				truncated = true
				return true, nil
			}
			out = append(out, item)
		}
		if len(out) >= lim.MaxItems {
			truncated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []IssueComment{}
	}
	return out, truncated || pageTrunc, nil
}

func projectComment(owner, repo string, number int, raw []byte) (IssueComment, error) {
	var wire struct {
		ID      int                    `json:"id"`
		Body    string                 `json:"body"`
		HTMLURL string                 `json:"html_url"`
		User    struct{ Login string } `json:"user"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.ID < 1 {
		return IssueComment{}, &APIError{kind: "response"}
	}
	got, ok := AcceptCommentURL(owner, repo, number, wire.ID, wire.HTMLURL)
	if !ok {
		return IssueComment{}, urlMiss(wire.HTMLURL)
	}
	return IssueComment{ID: wire.ID, User: safeLogin(wire.User.Login), Body: wire.Body, URL: got}, nil
}

// ReadPull reads the description, files, reviews, inline comments, and checks.
func ReadPull(ctx context.Context, client *http.Client, base, owner, repo string, number int, lim Limits) (PullDetail, error) {
	if !lim.ok() || number < 1 {
		return PullDetail{}, &APIError{kind: "transport"}
	}
	rawURL, err := apiURL(base, owner, repo, "/pulls/"+strconv.Itoa(number), "")
	if err != nil {
		return PullDetail{}, err
	}
	buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
	if err != nil {
		return PullDetail{}, err
	}
	var wire struct {
		HTMLURL string `json:"html_url"`
		Title   string `json:"title"`
		Body    string `json:"body"`
		State   string `json:"state"`
		Head    struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if json.Unmarshal(buf, &wire) != nil {
		return PullDetail{}, &APIError{kind: "response"}
	}
	got, ok := AcceptPullURL(owner, repo, wire.HTMLURL)
	if !ok || (wire.State != "open" && wire.State != "closed") || !PullBranch(wire.Head.Ref) || !PullBranch(wire.Base.Ref) || !commitSHA(wire.Head.SHA) {
		if !ok {
			return PullDetail{}, urlMiss(wire.HTMLURL)
		}
		return PullDetail{}, &APIError{kind: "response"}
	}
	out := PullDetail{
		URL: got, Title: wire.Title, Body: wire.Body, State: wire.State, Head: wire.Head.Ref, Base: wire.Base.Ref,
		Files: []PullFile{}, Reviews: []PullReview{}, Comments: []ReviewComment{}, Checks: []Check{},
		Statuses: []Check{}, Conversation: []IssueComment{},
	}
	files, fileTrunc, err := listFiles(ctx, client, base, owner, repo, number, lim)
	if err != nil {
		return PullDetail{}, err
	}
	reviews, reviewTrunc, err := listReviews(ctx, client, base, owner, repo, number, lim)
	if err != nil {
		return PullDetail{}, err
	}
	comments, commentTrunc, err := listReviewComments(ctx, client, base, owner, repo, number, lim)
	if err != nil {
		return PullDetail{}, err
	}
	checks, err := listChecks(ctx, client, base, owner, repo, wire.Head.SHA, lim)
	if err != nil {
		return PullDetail{}, err
	}
	conversation, convTrunc, err := ListIssueComments(ctx, client, base, owner, repo, number, lim)
	if err != nil {
		return PullDetail{}, err
	}
	out.Files, out.Reviews, out.Comments = files, reviews, comments
	out.Checks, out.Statuses = checks.Runs, checks.Statuses
	out.CombinedState = checks.Combined
	out.Conversation = conversation
	out.Truncated = fileTrunc || reviewTrunc || commentTrunc || checks.Truncated || convTrunc
	return out, nil
}

func listFiles(ctx context.Context, client *http.Client, base, owner, repo string, number int, lim Limits) ([]PullFile, bool, error) {
	var out []PullFile
	truncated := false
	pageTrunc, err := forPages(ctx, client, lim, func(page int) (string, error) {
		return apiURL(base, owner, repo, "/pulls/"+strconv.Itoa(number)+"/files", pageQuery(page, lim.PerPage, false))
	}, func(batch []json.RawMessage) (bool, error) {
		for _, raw := range batch {
			var wire struct {
				Name      string `json:"filename"`
				Status    string `json:"status"`
				Additions int    `json:"additions"`
				Deletions int    `json:"deletions"`
				Patch     string `json:"patch"`
			}
			if json.Unmarshal(raw, &wire) != nil || wire.Name == "" || strings.ContainsAny(wire.Name, "\r\n\x00") {
				return false, &APIError{kind: "response"}
			}
			if len(out) >= lim.MaxItems {
				truncated = true
				return true, nil
			}
			out = append(out, PullFile{
				Name: wire.Name, Status: safeToken(wire.Status), Additions: wire.Additions, Deletions: wire.Deletions, Patch: wire.Patch,
			})
		}
		if len(out) >= lim.MaxItems {
			truncated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []PullFile{}
	}
	return out, truncated || pageTrunc, nil
}

func listReviews(ctx context.Context, client *http.Client, base, owner, repo string, number int, lim Limits) ([]PullReview, bool, error) {
	var out []PullReview
	truncated := false
	pageTrunc, err := forPages(ctx, client, lim, func(page int) (string, error) {
		return apiURL(base, owner, repo, "/pulls/"+strconv.Itoa(number)+"/reviews", pageQuery(page, lim.PerPage, false))
	}, func(batch []json.RawMessage) (bool, error) {
		for _, raw := range batch {
			var wire struct {
				State string                 `json:"state"`
				Body  string                 `json:"body"`
				User  struct{ Login string } `json:"user"`
			}
			if json.Unmarshal(raw, &wire) != nil {
				return false, &APIError{kind: "response"}
			}
			if len(out) >= lim.MaxItems {
				truncated = true
				return true, nil
			}
			out = append(out, PullReview{User: safeLogin(wire.User.Login), State: safeToken(wire.State), Body: wire.Body})
		}
		if len(out) >= lim.MaxItems {
			truncated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []PullReview{}
	}
	return out, truncated || pageTrunc, nil
}

func listReviewComments(ctx context.Context, client *http.Client, base, owner, repo string, number int, lim Limits) ([]ReviewComment, bool, error) {
	var out []ReviewComment
	truncated := false
	pageTrunc, err := forPages(ctx, client, lim, func(page int) (string, error) {
		return apiURL(base, owner, repo, "/pulls/"+strconv.Itoa(number)+"/comments", pageQuery(page, lim.PerPage, false))
	}, func(batch []json.RawMessage) (bool, error) {
		for _, raw := range batch {
			var wire struct {
				Path     string                 `json:"path"`
				Body     string                 `json:"body"`
				DiffHunk string                 `json:"diff_hunk"`
				Line     *int                   `json:"line"`
				User     struct{ Login string } `json:"user"`
			}
			if json.Unmarshal(raw, &wire) != nil || strings.ContainsAny(wire.Path, "\r\n\x00") {
				return false, &APIError{kind: "response"}
			}
			if len(out) >= lim.MaxItems {
				truncated = true
				return true, nil
			}
			line := 0
			if wire.Line != nil && *wire.Line > 0 {
				line = *wire.Line
			}
			out = append(out, ReviewComment{
				User: safeLogin(wire.User.Login), Path: wire.Path, Line: line, Body: wire.Body, DiffHunk: wire.DiffHunk,
			})
		}
		if len(out) >= lim.MaxItems {
			truncated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, false, err
	}
	if out == nil {
		out = []ReviewComment{}
	}
	return out, truncated || pageTrunc, nil
}

// checkPage is one page of check runs plus the combined commit statuses.
// Statuses are always loaded so a legacy required status is not hidden
// behind a check run.
type checkPage struct {
	Runs      []Check
	Statuses  []Check
	Combined  string
	Truncated bool
}

func listChecks(ctx context.Context, client *http.Client, base, owner, repo, sha string, lim Limits) (checkPage, error) {
	if !commitSHA(sha) {
		return checkPage{}, &APIError{kind: "transport"}
	}
	var out checkPage
	start := lim.startPage()
	for n := 0; n < lim.MaxPages; n++ {
		page := start + n
		rawURL, err := apiURL(base, owner, repo, "/commits/"+sha+"/check-runs", pageQuery(page, lim.PerPage, false))
		if err != nil {
			return checkPage{}, err
		}
		buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
		if err != nil {
			return checkPage{}, err
		}
		var wire struct {
			Total int `json:"total_count"`
			Runs  []struct {
				Name       string  `json:"name"`
				Status     string  `json:"status"`
				Conclusion *string `json:"conclusion"`
			} `json:"check_runs"`
		}
		if json.Unmarshal(buf, &wire) != nil || wire.Total < 0 {
			return checkPage{}, &APIError{kind: "response"}
		}
		for _, run := range wire.Runs {
			if len(out.Runs) >= lim.MaxItems {
				out.Truncated = true
				break
			}
			conclusion := ""
			if run.Conclusion != nil {
				conclusion = *run.Conclusion
			}
			if conclusion == "" {
				conclusion = run.Status
			}
			out.Runs = append(out.Runs, Check{Name: clipPlain(run.Name, 80), Conclusion: safeToken(conclusion), Source: "check_run"})
		}
		full := len(wire.Runs) >= lim.PerPage
		if full || page*lim.PerPage < wire.Total {
			out.Truncated = true
		}
		if len(out.Runs) >= lim.MaxItems || !full {
			break
		}
	}
	statuses, combined, statusTrunc, err := listStatuses(ctx, client, base, owner, repo, sha)
	if err != nil {
		return checkPage{}, err
	}
	out.Statuses = statuses
	out.Combined = combined
	if statusTrunc {
		out.Truncated = true
	}
	if out.Runs == nil {
		out.Runs = []Check{}
	}
	return out, nil
}

func listStatuses(ctx context.Context, client *http.Client, base, owner, repo, sha string) ([]Check, string, bool, error) {
	rawURL, err := apiURL(base, owner, repo, "/commits/"+sha+"/status", "")
	if err != nil {
		return nil, "", false, err
	}
	buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
	if err != nil {
		return nil, "", false, err
	}
	var wire struct {
		State    string `json:"state"`
		Statuses []struct {
			Context string `json:"context"`
			State   string `json:"state"`
		} `json:"statuses"`
	}
	if json.Unmarshal(buf, &wire) != nil {
		return nil, "", false, &APIError{kind: "response"}
	}
	const statusCap = 100
	truncated := false
	out := make([]Check, 0, len(wire.Statuses))
	for _, st := range wire.Statuses {
		if len(out) >= statusCap {
			truncated = true
			break
		}
		out = append(out, Check{Name: clipPlain(st.Context, 80), Conclusion: safeToken(st.State), Source: "status"})
	}
	if out == nil {
		out = []Check{}
	}
	return out, safeToken(wire.State), truncated, nil
}

// CreateIssue posts one issue. rawURL is the proxy URL.
func CreateIssue(ctx context.Context, client *http.Client, rawURL, owner, repo string, in NewIssue) (CreatedIssue, error) {
	if !ValidIssueTitle(in.Title) || !ValidIssueBody(in.Body) {
		return CreatedIssue{}, &APIError{kind: "transport"}
	}
	payload := map[string]any{"title": in.Title}
	if in.Body != "" {
		payload["body"] = in.Body
	}
	buf, err := doGitHub(ctx, client, http.MethodPost, rawURL, payload, http.StatusCreated)
	if err != nil {
		return CreatedIssue{}, err
	}
	var wire struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(buf, &wire) != nil {
		return CreatedIssue{}, &APIError{kind: "unverified"}
	}
	got, n, ok := AcceptIssueURL(owner, repo, wire.HTMLURL)
	if !ok || n != wire.Number {
		return CreatedIssue{}, &APIError{kind: "unverified"}
	}
	return CreatedIssue{URL: got, Number: n}, nil
}

// CreateComment posts one issue or pull-request conversation comment.
func CreateComment(ctx context.Context, client *http.Client, rawURL, owner, repo string, number int, body string) (CreatedComment, error) {
	if number < 1 || !ValidCommentBody(body) {
		return CreatedComment{}, &APIError{kind: "transport"}
	}
	buf, err := doGitHub(ctx, client, http.MethodPost, rawURL, map[string]any{"body": body}, http.StatusCreated)
	if err != nil {
		return CreatedComment{}, err
	}
	var wire struct {
		ID      int    `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(buf, &wire) != nil || wire.ID < 1 {
		return CreatedComment{}, &APIError{kind: "unverified"}
	}
	got, ok := AcceptCommentURL(owner, repo, number, wire.ID, wire.HTMLURL)
	if !ok {
		return CreatedComment{}, &APIError{kind: "unverified"}
	}
	return CreatedComment{URL: got, ID: wire.ID}, nil
}

// forPages calls handle once per page. The bool is true when every page was
// full, so the caller hit the page cap and more results may exist.
func forPages(ctx context.Context, client *http.Client, lim Limits, rawURL func(page int) (string, error), handle func([]json.RawMessage) (bool, error)) (bool, error) {
	start := lim.startPage()
	for n := 0; n < lim.MaxPages; n++ {
		page := start + n
		u, err := rawURL(page)
		if err != nil {
			return false, err
		}
		buf, err := doGitHub(ctx, client, http.MethodGet, u, nil, http.StatusOK)
		if err != nil {
			return false, err
		}
		var batch []json.RawMessage
		if json.Unmarshal(buf, &batch) != nil {
			return false, &APIError{kind: "response"}
		}
		stop, err := handle(batch)
		if err != nil {
			return false, err
		}
		if stop || len(batch) < lim.PerPage {
			return false, nil
		}
	}
	return true, nil
}

func pageQuery(page, per int, open bool) string {
	q := "page=" + strconv.Itoa(page) + "&per_page=" + strconv.Itoa(per)
	if open {
		q += "&state=open"
	}
	return q
}

func apiURL(base, owner, repo, tail, query string) (string, error) {
	name, err := NormalizeRepo(owner + "/" + repo)
	if err != nil || name != owner+"/"+repo {
		return "", &APIError{kind: "transport"}
	}
	if !strings.HasPrefix(tail, "/") || strings.ContainsAny(tail, "\r\n\t\x00 ?#") || strings.Contains(tail, "//") {
		return "", &APIError{kind: "transport"}
	}
	if strings.ContainsAny(base, "\r\n\t\x00 ") || !strings.Contains(base, "://") {
		return "", &APIError{kind: "transport"}
	}
	u := strings.TrimRight(base, "/") + "/repos/" + owner + "/" + repo + tail
	if query != "" {
		u += "?" + query
	}
	return u, nil
}

// LookupTarget reads one issue record. A pull-request html_url is accepted
// as kind pull so a comment card can name the pull request. GetIssue stays
// strict and still requires an issue URL.
func LookupTarget(ctx context.Context, client *http.Client, base, owner, repo string, number int) (IssueTarget, error) {
	rawURL, err := apiURL(base, owner, repo, "/issues/"+strconv.Itoa(number), "")
	if err != nil || number < 1 {
		return IssueTarget{}, &APIError{kind: "transport"}
	}
	buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
	if err != nil {
		return IssueTarget{}, err
	}
	var wire struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		State   string `json:"state"`
		HTMLURL string `json:"html_url"`
	}
	if json.Unmarshal(buf, &wire) != nil || wire.Number != number {
		return IssueTarget{}, &APIError{kind: "response"}
	}
	if wire.State != "open" && wire.State != "closed" {
		return IssueTarget{}, &APIError{kind: "response"}
	}
	if got, n, ok := AcceptIssueURL(owner, repo, wire.HTMLURL); ok && n == number {
		return IssueTarget{Kind: "issue", Title: wire.Title, State: wire.State, URL: got}, nil
	}
	if got, ok := AcceptPullURL(owner, repo, wire.HTMLURL); ok && urlNumber(got) == number {
		return IssueTarget{Kind: "pull", Title: wire.Title, State: wire.State, URL: got}, nil
	}
	return IssueTarget{}, urlMiss(wire.HTMLURL)
}

// urlMiss is a moved or renamed GitHub URL when the host is github.com,
// and a response error otherwise.
func urlMiss(raw string) error {
	if githubHostURL(raw) {
		return &APIError{kind: "moved"}
	}
	return &APIError{kind: "response"}
}

func githubHostURL(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t\x00 ") || len(raw) > 300 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "github.com") || u.User != nil {
		return false
	}
	return true
}

func safeLogin(s string) string {
	if s == "" || len(s) > 39 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return ""
		}
	}
	return s
}

func safeToken(s string) string {
	if s == "" || len(s) > 40 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return ""
		}
	}
	return s
}

func clipPlain(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// checkIssueBody reads an issue body up to a fixed limit. Keys must be the
// exact lowercase names title and body. title is required. Any other key,
// a duplicate, or a non-string value is refused. The original bytes are returned.
func checkIssueBody(r io.Reader) (io.Reader, error) {
	buf, err := readJSONBody(r)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errPkt
	}
	seen := map[string]bool{}
	sawTitle := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, errPkt
		}
		key, ok := keyTok.(string)
		if !ok || seen[key] {
			return nil, errPkt
		}
		seen[key] = true
		val, err := dec.Token()
		if err != nil {
			return nil, errPkt
		}
		s, ok := val.(string)
		if !ok {
			return nil, errPkt
		}
		switch key {
		case "title":
			if strings.TrimSpace(s) == "" {
				return nil, errPkt
			}
			sawTitle = true
		case "body":
		default:
			return nil, errPkt
		}
	}
	if !sawTitle || !jsonObjectEnd(dec) {
		return nil, errPkt
	}
	return bytes.NewReader(buf), nil
}

// checkCommentBody reads a comment body. The only key is body, a string.
func checkCommentBody(r io.Reader) (io.Reader, error) {
	buf, err := readJSONBody(r)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errPkt
	}
	if !dec.More() {
		return nil, errPkt
	}
	keyTok, err := dec.Token()
	if err != nil {
		return nil, errPkt
	}
	key, ok := keyTok.(string)
	if !ok || key != "body" {
		return nil, errPkt
	}
	val, err := dec.Token()
	if err != nil {
		return nil, errPkt
	}
	s, ok := val.(string)
	if !ok || strings.TrimSpace(s) == "" || dec.More() || !jsonObjectEnd(dec) {
		return nil, errPkt
	}
	return bytes.NewReader(buf), nil
}

func readJSONBody(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errPkt
	}
	buf, err := io.ReadAll(io.LimitReader(r, maxPullBody+1))
	if err != nil || len(buf) == 0 || len(buf) > maxPullBody {
		return nil, errPkt
	}
	return buf, nil
}

func jsonObjectEnd(dec *json.Decoder) bool {
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	var extra any
	return dec.Decode(&extra) == io.EOF
}
