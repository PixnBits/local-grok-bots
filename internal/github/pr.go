package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIError is a GitHub call that failed. The text is a status or a fixed
// reason. It never includes the response body.
type APIError struct {
	Status int
	kind   string
}

func (e *APIError) Error() string {
	if e == nil {
		return "github unavailable"
	}
	if e.kind == "status" && e.Status >= 100 && e.Status <= 599 {
		return fmt.Sprintf("github status %d", e.Status)
	}
	if e.kind == "response" {
		return "github response"
	}
	return "github unavailable"
}

// PullRequest is the projection returned to the model.
type PullRequest struct {
	URL   string
	State string
	Draft bool
	Head  string
	Base  string
}

// NewPull is a pull request the daemon is allowed to send.
type NewPull struct {
	Title string
	Body  string
	Head  string
	Base  string
	Draft bool
}

// PullBranch accepts a branch name and refuses refs/, refspecs, and force.
func PullBranch(s string) bool {
	if s == "" || strings.HasPrefix(s, "refs/") || strings.Contains(s, ":") {
		return false
	}
	return BranchOK(s)
}

// ValidPullTitle reports whether title can be sent as a pull request title.
func ValidPullTitle(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	return pullText(s, 256, false)
}

// ValidPullBody reports whether body can be sent. Empty is allowed.
func ValidPullBody(s string) bool {
	return pullText(s, 1<<16, true)
}

func pullText(s string, max int, allowNL bool) bool {
	if len(s) > max || strings.ContainsRune(s, 0) {
		return false
	}
	for _, r := range s {
		if r == 0x7f || r < 0x20 {
			if allowNL && (r == '\n' || r == '\t') {
				continue
			}
			return false
		}
	}
	return true
}

// AcceptPullURL accepts https://github.com/owner/repo/pull/N for this repo.
// The returned URL is rebuilt. The raw string is not passed through.
func AcceptPullURL(owner, repo, raw string) (string, bool) {
	if strings.ContainsAny(raw, "\r\n\t\x00 ") || len(raw) > 300 {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return "", false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[2] != "pull" {
		return "", false
	}
	if !strings.EqualFold(parts[0], owner) || !strings.EqualFold(parts[1], repo) {
		return "", false
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n < 1 || strconv.Itoa(n) != parts[3] {
		return "", false
	}
	return "https://github.com/" + owner + "/" + repo + "/pull/" + parts[3], true
}

// CreatePull posts one pull request. rawURL is the proxy URL. The client
// must not carry the token. A non-201 or an unsafe URL fails closed.
func CreatePull(ctx context.Context, client *http.Client, rawURL, owner, repo string, in NewPull) (PullRequest, error) {
	if !PullBranch(in.Head) || !PullBranch(in.Base) || !ValidPullTitle(in.Title) || !ValidPullBody(in.Body) {
		return PullRequest{}, &APIError{kind: "transport"}
	}
	buf, err := doGitHub(ctx, client, http.MethodPost, rawURL, map[string]any{
		"title": in.Title,
		"body":  in.Body,
		"head":  in.Head,
		"base":  in.Base,
		"draft": in.Draft,
	}, http.StatusCreated)
	if err != nil {
		return PullRequest{}, err
	}
	return projectPull(owner, repo, buf, false)
}

// GetPull reads one pull request and projects the fields the model may see.
func GetPull(ctx context.Context, client *http.Client, rawURL, owner, repo string) (PullRequest, error) {
	buf, err := doGitHub(ctx, client, http.MethodGet, rawURL, nil, http.StatusOK)
	if err != nil {
		return PullRequest{}, err
	}
	return projectPull(owner, repo, buf, true)
}

func projectPull(owner, repo string, buf []byte, full bool) (PullRequest, error) {
	var wire struct {
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
		Draft   bool   `json:"draft"`
		Head    struct {
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if json.Unmarshal(buf, &wire) != nil {
		return PullRequest{}, &APIError{kind: "response"}
	}
	got, ok := AcceptPullURL(owner, repo, wire.HTMLURL)
	if !ok {
		return PullRequest{}, &APIError{kind: "response"}
	}
	out := PullRequest{URL: got, Draft: wire.Draft}
	if !full {
		return out, nil
	}
	if wire.State != "open" && wire.State != "closed" {
		return PullRequest{}, &APIError{kind: "response"}
	}
	if !PullBranch(wire.Head.Ref) || !PullBranch(wire.Base.Ref) {
		return PullRequest{}, &APIError{kind: "response"}
	}
	out.State = wire.State
	out.Head = wire.Head.Ref
	out.Base = wire.Base.Ref
	return out, nil
}

func doGitHub(ctx context.Context, client *http.Client, method, rawURL string, payload any, want int) ([]byte, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if strings.ContainsAny(rawURL, "\r\n\t\x00 ") || !strings.Contains(rawURL, "://") {
		return nil, &APIError{kind: "transport"}
	}
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, &APIError{kind: "transport"}
		}
		body = bytes.NewReader(b)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, &APIError{kind: "transport"}
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &APIError{kind: "transport"}
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &APIError{kind: "transport"}
	}
	if resp.StatusCode != want {
		return nil, &APIError{Status: resp.StatusCode, kind: "status"}
	}
	return buf, nil
}
