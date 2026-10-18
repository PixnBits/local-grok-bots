package coi

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
)

const (
	sourceManaged  = "managed"
	sourceLocal    = "local"
	sourceBot      = "bot"
	sourceDefault  = "default"
	sourceNoNet    = "no_net"
	removedInvalid = "invalid"
)

// filterServerTools strips non-function tools from a gated request body.
// allowOf is called only when the body has a tools array to filter. It
// returns the non-function types that may stay, and the source of that
// decision. A nil or empty allow list strips every non-function type.
// Function tools stay. reason is empty on success. Otherwise it is
// duplicate_key or unparsed, and the caller answers 403 and audits
// cli_proxy_refused. A passing call with a non-empty body leaves a
// freshly re-encoded body and a Content-Length that matches it. The
// original bytes are not forwarded. An empty body is left unread.
func filterServerTools(r *http.Request, allowOf func() ([]string, string)) (removed []string, source, reason string) {
	if r == nil || r.Body == nil || r.ContentLength == 0 {
		return nil, "", ""
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxModelBody+1))
	if err != nil || len(raw) > maxModelBody {
		return nil, "", refuseUnparsed
	}
	if len(raw) == 0 {
		restoreBody(r, raw)
		return nil, "", ""
	}
	encs, ok := contentEncodings(r.Header.Get("Content-Encoding"))
	if !ok {
		return nil, "", refuseUnparsed
	}
	decoded := raw
	if len(encs) > 0 {
		decoded, err = decodeEncodings(raw, encs)
		if err != nil || len(decoded) > maxModelBody {
			return nil, "", refuseUnparsed
		}
	}
	if len(decoded) == 0 {
		return nil, "", refuseUnparsed
	}
	rewritten, removed, source, reason := rewriteTools(decoded, allowOf)
	if reason != "" {
		return nil, "", reason
	}
	if strings.TrimSpace(r.Header.Get("Content-Encoding")) != "" {
		r.Header.Del("Content-Encoding")
	}
	restoreBody(r, rewritten)
	return uniqueToolTypes(removed), source, ""
}

func contentEncodings(h string) ([]string, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil, true
	}
	var out []string
	for _, part := range strings.Split(h, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" || p == "identity" {
			continue
		}
		switch p {
		case "gzip", "x-gzip", "deflate":
			out = append(out, p)
		default:
			// br and zstd are not vendored. Any other coding is refused.
			return nil, false
		}
	}
	if len(out) > 2 {
		return nil, false
	}
	return out, true
}

func decodeEncodings(body []byte, encs []string) ([]byte, error) {
	cur := body
	for i := len(encs) - 1; i >= 0; i-- {
		next, err := decodeOne(cur, encs[i])
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

func decodeOne(body []byte, enc string) ([]byte, error) {
	switch enc {
	case "gzip", "x-gzip":
		return decodeGzip(body)
	case "deflate":
		if out, err := decodeZlib(body); err == nil {
			return out, nil
		}
		return decodeRawDeflate(body)
	default:
		return nil, errors.New("unsupported content encoding")
	}
}

func decodeGzip(body []byte) ([]byte, error) {
	in := bytes.NewReader(body)
	zr, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}
	out, err := readAtMost(zr)
	cerr := zr.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	if in.Len() != 0 {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

func decodeZlib(body []byte) ([]byte, error) {
	in := bytes.NewReader(body)
	zr, err := zlib.NewReader(in)
	if err != nil {
		return nil, err
	}
	out, err := readAtMost(zr)
	cerr := zr.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	if in.Len() != 0 {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

func decodeRawDeflate(body []byte) ([]byte, error) {
	in := bytes.NewReader(body)
	fr := flate.NewReader(in)
	out, err := readAtMost(fr)
	cerr := fr.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	if in.Len() != 0 {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

func readAtMost(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(maxModelBody)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxModelBody {
		return nil, errors.New("model body is too large")
	}
	return b, nil
}

// maxJSONDepth is how deep a request object or array may nest. Deeper
// input is refused so a nested document cannot exhaust the stack.
const maxJSONDepth = 64

var errDuplicateKey = errors.New("duplicate key")

// rewriteTools checks the decoded body and returns the bytes to forward.
// A successful parse is always re-encoded. Duplicate keys and invalid
// JSON refuse. allowOf runs only when a tools array needs a decision.
func rewriteTools(body []byte, allowOf func() ([]string, string)) (out []byte, removed []string, source, reason string) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil, "", refuseUnparsed
	}
	if err := scanJSON(body); err != nil {
		if errors.Is(err, errDuplicateKey) {
			return nil, nil, "", refuseDuplicateKey
		}
		return nil, nil, "", refuseUnparsed
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, "", refuseUnparsed
	}
	if reason := refusedToolsSpelling(v); reason != "" {
		return nil, nil, "", reason
	}
	removed, source, bad := filterToolsValue(v, allowOf)
	if bad {
		return nil, nil, "", refuseUnparsed
	}
	encoded, err := marshalCanonical(v)
	if err != nil {
		return nil, nil, "", refuseUnparsed
	}
	return encoded, removed, source, ""
}

// scanJSON walks every token. A repeated object key at any depth is
// errDuplicateKey. Trailing data and a nest past maxJSONDepth are errors.
func scanJSON(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	dup, err := walkJSON(dec, 1)
	if err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("trailing json")
		}
		return err
	}
	if dup {
		return errDuplicateKey
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) (bool, error) {
	if depth > maxJSONDepth {
		return false, errors.New("json is too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false, nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		dup := false
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyTok.(string)
			if !ok {
				return false, errors.New("object key")
			}
			if _, exists := seen[key]; exists {
				dup = true
			} else {
				seen[key] = struct{}{}
			}
			child, err := walkJSON(dec, depth+1)
			if err != nil {
				return false, err
			}
			dup = dup || child
		}
		end, err := dec.Token()
		if err != nil {
			return false, err
		}
		if d, ok := end.(json.Delim); !ok || d != '}' {
			return false, errors.New("object end")
		}
		return dup, nil
	case '[':
		dup := false
		for dec.More() {
			child, err := walkJSON(dec, depth+1)
			if err != nil {
				return false, err
			}
			dup = dup || child
		}
		end, err := dec.Token()
		if err != nil {
			return false, err
		}
		if d, ok := end.(json.Delim); !ok || d != ']' {
			return false, errors.New("array end")
		}
		return dup, nil
	default:
		return false, errors.New("json delim")
	}
}

// marshalCanonical writes v with sorted object keys and no HTML escaping.
// json.Number values keep the literal from the request.
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

const (
	toolDrop = iota
	toolKeepFunction
	toolKeepAllowed
)

// refusedToolsSpelling rejects a top-level key that equals "tools" or
// "tool_choice" ignoring case but is not that exact spelling. The exact
// keys are filtered. A different spelling would otherwise be forwarded whole.
func refusedToolsSpelling(v any) string {
	top, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	for k := range top {
		if k == "tools" || k == "tool_choice" {
			continue
		}
		if strings.EqualFold(k, "tools") || strings.EqualFold(k, "tool_choice") {
			return refuseToolsKey
		}
	}
	return ""
}

// filterToolsValue strips non-function tools from a top-level tools key.
// A value that is not an object, or an object with no tools key, is kept.
// tools that is not an array is bad. allowOf is not called unless tools
// is a non-empty array.
func filterToolsValue(v any, allowOf func() ([]string, string)) (removed []string, source string, bad bool) {
	top, ok := v.(map[string]any)
	if !ok {
		return nil, "", false
	}
	raw, ok := top["tools"]
	if !ok || raw == nil {
		return nil, "", false
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, "", true
	}
	if len(entries) == 0 {
		return nil, "", false
	}
	allow, source := []string(nil), sourceDefault
	if allowOf != nil {
		allow, source = allowOf()
	}
	allowSet := map[string]bool{}
	for _, name := range normalizeAllow(allow) {
		allowSet[name] = true
	}
	var kept []any
	var gone []string
	for _, entry := range entries {
		typ, kind := toolEntryType(entry)
		switch kind {
		case toolKeepFunction:
			kept = append(kept, entry)
		case toolKeepAllowed:
			if allowSet[typ] {
				kept = append(kept, entry)
				continue
			}
			gone = append(gone, typ)
		default:
			gone = append(gone, removedInvalid)
		}
	}
	if len(gone) == 0 {
		return nil, "", false
	}
	if len(kept) == 0 {
		delete(top, "tools")
	} else {
		top["tools"] = kept
	}
	removedSet := map[string]bool{}
	for _, name := range gone {
		removedSet[name] = true
	}
	adjustToolChoice(top, removedSet, len(kept) > 0)
	return gone, source, false
}

func toolEntryType(entry any) (string, int) {
	obj, ok := entry.(map[string]any)
	if !ok || obj == nil {
		return "", toolDrop
	}
	raw, ok := obj["type"]
	if !ok {
		return "", toolDrop
	}
	typ, ok := jsonTypeName(raw)
	if !ok {
		return "", toolDrop
	}
	if typ == "function" {
		return typ, toolKeepFunction
	}
	if !safeToolType(typ) {
		return "", toolDrop
	}
	return typ, toolKeepAllowed
}

func jsonTypeName(raw any) (string, bool) {
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	return s, true
}

func safeToolType(s string) bool {
	if s == "" || s == "function" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func normalizeAllow(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if !safeToolType(s) || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func uniqueToolTypes(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != removedInvalid && !safeToolType(s) {
			s = removedInvalid
		}
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// adjustToolChoice drops a choice that names a removed type, or that
// requires a tool after the tools list is gone. When tools remain, a
// choice that named a removed type becomes "auto".
func adjustToolChoice(top map[string]any, removed map[string]bool, toolsLeft bool) {
	raw, ok := top["tool_choice"]
	if !ok {
		return
	}
	if raw == nil {
		if !toolsLeft {
			delete(top, "tool_choice")
		}
		return
	}
	if s, ok := raw.(string); ok {
		low := strings.ToLower(s)
		if removed[low] || (low == "required" && !toolsLeft) {
			neutralizeChoice(top, toolsLeft)
		}
		return
	}
	obj, ok := raw.(map[string]any)
	if !ok || obj == nil {
		neutralizeChoice(top, toolsLeft)
		return
	}
	if choicePointsAt(obj, removed) || (choiceIsRequired(obj) && !toolsLeft) {
		neutralizeChoice(top, toolsLeft)
	}
}

func neutralizeChoice(top map[string]any, toolsLeft bool) {
	if toolsLeft {
		top["tool_choice"] = "auto"
		return
	}
	delete(top, "tool_choice")
}

func choiceIsRequired(obj map[string]any) bool {
	typ, ok := jsonTypeName(obj["type"])
	if ok && typ == "required" {
		return true
	}
	mode, ok := jsonTypeName(obj["mode"])
	return ok && mode == "required" && !okType(obj, "function")
}

func okType(obj map[string]any, want string) bool {
	typ, ok := jsonTypeName(obj["type"])
	return ok && typ == want
}

func choicePointsAt(obj map[string]any, removed map[string]bool) bool {
	if raw, ok := obj["type"]; ok {
		typ, good := jsonTypeName(raw)
		if !good || removed[typ] {
			return true
		}
	}
	if raw, ok := obj["name"]; ok {
		name, good := jsonTypeName(raw)
		if !good || removed[name] {
			return true
		}
	}
	raw, ok := obj["tools"]
	if !ok {
		return false
	}
	arr, ok := raw.([]any)
	if !ok {
		return true
	}
	for _, el := range arr {
		one, ok := el.(map[string]any)
		if !ok || one == nil {
			return true
		}
		if raw, ok := one["type"]; ok {
			typ, good := jsonTypeName(raw)
			if !good || removed[typ] {
				return true
			}
		}
		if raw, ok := one["name"]; ok {
			name, good := jsonTypeName(raw)
			if !good || removed[name] {
				return true
			}
		}
	}
	return false
}
