package coi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

// tokenEndpoint is the OIDC refresh URL for auth.x.ai. Tests may replace it.
var tokenEndpoint = "https://auth.x.ai/oauth2/token"

// ProxyRequired reports whether the call must go through the egress proxy.
func ProxyRequired(tool policy.CLITool) bool {
	return len(tool.ProxyHosts) > 0
}

// UsesJailCredentials reports whether real credential bytes are copied into
// the jail. That path exists only when managed policy opted in and proxy
// mode is not in use.
func UsesJailCredentials(tool policy.CLITool) bool {
	if ProxyRequired(tool) || len(tool.CredentialFiles) == 0 {
		return false
	}
	return tool.AllowJailCredentials
}

// JailCredentialGate denies credential_files combined with --always-approve
// when the proxy is not used and managed policy did not opt in.
func JailCredentialGate(tool policy.CLITool) error {
	if ProxyRequired(tool) || len(tool.CredentialFiles) == 0 || !fixedAlwaysApprove(tool.FixedArgs) {
		return nil
	}
	if tool.AllowJailCredentials {
		return nil
	}
	return ErrJailCredentials
}

func fixedAlwaysApprove(args []string) bool {
	for _, a := range args {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "--always-approve" || strings.HasPrefix(a, "--always-approve=") {
			return true
		}
	}
	return false
}

// ProxyPreflight checks that a bearer token can be read. It does not refresh.
func ProxyPreflight(tool policy.CLITool) error {
	if !ProxyRequired(tool) {
		return nil
	}
	cred, err := loadGrokCred(tool.CredentialHome, tool.CredentialFiles)
	if err != nil || (cred.key == "" && cred.refresh == "") {
		return ErrProxyUnavailable
	}
	if cred.key == "" || (!cred.expires.IsZero() && !cred.expires.After(time.Now()) && cred.refresh == "") {
		return ErrProxyUnavailable
	}
	return nil
}

// AccessToken returns the host bearer for the proxy, refreshing when the
// access token is near expiry. The refreshed token is written back to the
// credential file. A refresh can rotate the refresh token.
func AccessToken(tool policy.CLITool) (string, error) {
	cred, err := loadGrokCred(tool.CredentialHome, tool.CredentialFiles)
	if err != nil || cred.key == "" && cred.refresh == "" {
		return "", ErrProxyUnavailable
	}
	if cred.expires.IsZero() || cred.expires.After(time.Now().Add(90*time.Second)) {
		if cred.key == "" {
			return "", ErrProxyUnavailable
		}
		return cred.key, nil
	}
	if cred.refresh == "" {
		if cred.key != "" && cred.expires.After(time.Now()) {
			return cred.key, nil
		}
		return "", ErrProxyUnavailable
	}
	next, err := refreshGrok(cred)
	if err != nil {
		if cred.key != "" && cred.expires.After(time.Now().Add(5*time.Second)) {
			return cred.key, nil
		}
		return "", ErrProxyUnavailable
	}
	return next, nil
}

type grokCred struct {
	path     string
	mapKey   string
	key      string
	refresh  string
	expires  time.Time
	clientID string
	doc      map[string]map[string]any
}

func loadGrokCred(home string, files []string) (grokCred, error) {
	rels := append([]string{}, files...)
	rels = append(rels, ".grok/auth.json", "auth.json")
	seen := map[string]bool{}
	var last error
	for _, rel := range rels {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		clean := filepath.Clean(rel)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		if filepath.IsAbs(clean) || strings.HasPrefix(filepath.ToSlash(clean), "../") {
			continue
		}
		path := filepath.Join(home, clean)
		if !hasPathPrefix(filepath.Clean(home), path) {
			continue
		}
		cred, err := parseGrokAuth(path)
		if err != nil {
			last = err
			continue
		}
		if cred.key != "" || cred.refresh != "" {
			return cred, nil
		}
	}
	if last != nil {
		return grokCred{}, last
	}
	return grokCred{}, ErrProxyUnavailable
}

func parseGrokAuth(path string) (grokCred, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return grokCred{}, err
	}
	var doc map[string]map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return grokCred{}, err
	}
	var cred grokCred
	for k, ent := range doc {
		if ent == nil {
			continue
		}
		key, _ := ent["key"].(string)
		refresh, _ := ent["refresh_token"].(string)
		if key == "" && refresh == "" {
			continue
		}
		cred.path = path
		cred.mapKey = k
		cred.key = key
		cred.refresh = refresh
		cred.doc = doc
		if id, ok := ent["oidc_client_id"].(string); ok {
			cred.clientID = id
		}
		if s, ok := ent["expires_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				cred.expires = t
			}
		}
		return cred, nil
	}
	return grokCred{}, errors.New("no token")
}

func refreshGrok(cred grokCred) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", cred.refresh)
	if cred.clientID != "" {
		form.Set("client_id", cred.clientID)
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("token refresh failed")
	}
	var parsed struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Expires int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Access == "" {
		return "", errors.New("token refresh failed")
	}
	ent := cred.doc[cred.mapKey]
	if ent == nil {
		return "", errors.New("token refresh failed")
	}
	ent["key"] = parsed.Access
	if parsed.Refresh != "" {
		ent["refresh_token"] = parsed.Refresh
	}
	exp := time.Now().UTC().Add(time.Duration(parsed.Expires) * time.Second)
	if parsed.Expires <= 0 {
		exp = time.Now().UTC().Add(time.Hour)
	}
	ent["expires_at"] = exp.Format(time.RFC3339Nano)
	out, err := json.Marshal(cred.doc)
	if err != nil {
		return "", err
	}
	tmp := cred.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, cred.path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return parsed.Access, nil
}
