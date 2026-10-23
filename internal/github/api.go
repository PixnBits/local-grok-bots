package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// ErrLookup means the default branch could not be read. The error has no body.
var ErrLookup = errors.New("default branch lookup failed")

// DefaultBranch reads default_branch from a GET that already goes through the
// credential proxy. The client must not carry the token. A non-200, a missing
// field, or an unsafe branch name fails closed.
func DefaultBranch(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.ContainsAny(rawURL, "\r\n\t\x00 ") || !strings.Contains(rawURL, "://") {
		return "", ErrLookup
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", ErrLookup
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", ErrLookup
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", ErrLookup
	}
	if resp.StatusCode != http.StatusOK {
		return "", ErrLookup
	}
	var doc struct {
		DefaultBranch string `json:"default_branch"`
	}
	if json.Unmarshal(body, &doc) != nil || !BranchOK(doc.DefaultBranch) {
		return "", ErrLookup
	}
	return doc.DefaultBranch, nil
}
