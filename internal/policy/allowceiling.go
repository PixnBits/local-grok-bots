package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

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

// ceilingKeyPresent reports the exact ceiling key among decoded map keys.
// A decode failure reports the key as absent so the caller can use its
// own parse error. Text inside a string value is not a key.
func ceilingKeyPresent(body []byte, path string) bool {
	keys, ok := decodedMapKeys(body, path)
	if !ok {
		return false
	}
	for _, key := range keys {
		if key == allowCeilingKey {
			return true
		}
	}
	return false
}

// ceilingKeySpelling rejects a folded spelling of a decoded key.
// The check uses the key after escapes are decoded. A decode failure
// returns nil so the real parser reports that error.
func ceilingKeySpelling(body []byte, path string) error {
	keys, ok := decodedMapKeys(body, path)
	if !ok {
		return nil
	}
	folded := strings.ToLower(allowCeilingKey)
	for _, key := range keys {
		if strings.ToLower(key) == folded && key != allowCeilingKey {
			return fmt.Errorf("%w: key must be spelled %s", errAllowCeiling, allowCeilingKey)
		}
	}
	return nil
}

func decodedMapKeys(body []byte, path string) ([]string, bool) {
	var v any
	var err error
	if strings.ToLower(filepath.Ext(path)) == ".json" {
		err = json.Unmarshal(body, &v)
	} else {
		err = toml.Unmarshal(body, &v)
	}
	if err != nil {
		return nil, false
	}
	return collectMapKeys(v), true
}

func collectMapKeys(v any) []string {
	var keys []string
	var walk func(any)
	walk = func(n any) {
		switch x := n.(type) {
		case map[string]any:
			for k, child := range x {
				keys = append(keys, k)
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	return keys
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
