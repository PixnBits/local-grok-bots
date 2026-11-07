package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/permbroker"
)

// errAllowCeiling is a hard policy-load error. Load returns it, so the
// daemon refuses to start. It is not the soft fail-closed path.
var errAllowCeiling = errors.New("cli.permission.dangerouslyAllowAllPermissionRequestsUpThrough is invalid")

func parseAllowThrough(raw any) (map[string]permbroker.Level, error) {
	m, err := ceilingMap(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]permbroker.Level, len(m))
	for key, val := range m {
		key = strings.TrimSpace(key)
		if key == "" || strings.ContainsAny(key, "*?") {
			return nil, fmt.Errorf("%w: wildcard key %q", errAllowCeiling, key)
		}
		id, ok := canonicalBotUUID(key)
		if !ok {
			return nil, fmt.Errorf("%w: bot id %q is not a UUID", errAllowCeiling, key)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("%w: duplicate bot id %s", errAllowCeiling, id)
		}
		s, ok := val.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("%w: missing or empty value for %s", errAllowCeiling, id)
		}
		// No trim and no case folding. " low " and "HIGH" are unknown.
		lvl, ok := permbroker.AllowCeilingLevel(s)
		if !ok {
			return nil, fmt.Errorf("%w: unknown level %q", errAllowCeiling, s)
		}
		out[id] = lvl
	}
	return out, nil
}

// allowCeilingKey is the only accepted spelling of the ceiling table.
const allowCeilingKey = "dangerouslyAllowAllPermissionRequestsUpThrough"

// ceilingKeyPresent reports the exact ceiling key outside a comment.
func ceilingKeyPresent(body []byte) bool {
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if i := strings.Index(trim, " #"); i >= 0 {
			trim = strings.TrimSpace(trim[:i])
		}
		if strings.Contains(trim, allowCeilingKey) {
			return true
		}
	}
	return false
}

// ceilingKeySpelling rejects a folded spelling of the ceiling key.
// Comments are skipped. The letters must match exactly.
func ceilingKeySpelling(body []byte) error {
	folded := strings.ToLower(allowCeilingKey)
	for _, line := range strings.Split(string(body), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if i := strings.Index(trim, " #"); i >= 0 {
			trim = strings.TrimSpace(trim[:i])
		}
		if strings.Contains(strings.ToLower(trim), folded) && !strings.Contains(trim, allowCeilingKey) {
			return fmt.Errorf("%w: key must be spelled %s", errAllowCeiling, allowCeilingKey)
		}
	}
	return nil
}

func ceilingMap(raw any) (map[string]any, error) {
	switch m := raw.(type) {
	case map[string]any:
		return m, nil
	case map[string]string:
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: must be a map", errAllowCeiling)
	}
}

// checkCeilingBots rejects a ceiling whose bot is not listed in broker_bots.
// An empty broker_bots list does not mean every bot for this key. A ceiling
// must not widen the broker set.
func checkCeilingBots(bots []string, ceilings map[string]permbroker.Level) error {
	for id := range ceilings {
		if !brokerListsBot(bots, id) {
			return fmt.Errorf("%w: bot %s is not in broker_bots", errAllowCeiling, id)
		}
	}
	return nil
}

func brokerListsBot(bots []string, id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return false
	}
	for _, b := range bots {
		if strings.ToLower(strings.TrimSpace(b)) == id {
			return true
		}
	}
	return false
}

// canonicalBotUUID accepts the 8-4-4-4-12 text form and returns lowercase.
func canonicalBotUUID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 {
		return "", false
	}
	widths := []int{8, 4, 4, 4, 12}
	i := 0
	for n, w := range widths {
		if n > 0 {
			if s[i] != '-' {
				return "", false
			}
			i++
		}
		for k := 0; k < w; k++ {
			c := s[i+k]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return "", false
			}
		}
		i += w
	}
	return s, true
}
