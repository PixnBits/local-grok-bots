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

// filterServerTools strips non-function tools from a model request.
// allow is the set of non-function types that may stay. A nil or empty
// allow list strips every non-function type. Function tools stay.
// refuse is true when the body cannot be filtered safely. The caller
// answers 403 and audits cli_proxy_refused. A passing call leaves a
// readable body and a Content-Length that matches it.
func filterServerTools(r *http.Request, allow []string) (removed []string, refuse bool) {
	if !modelRequest(r) {
		return nil, false
	}
	if r.Body == nil || r.ContentLength == 0 {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxModelBody+1))
	if err != nil || len(raw) > maxModelBody {
		return nil, true
	}
	encs, ok := contentEncodings(r.Header.Get("Content-Encoding"))
	if !ok {
		return nil, true
	}
	decoded := raw
	if len(encs) > 0 {
		decoded, err = decodeEncodings(raw, encs)
		if err != nil || len(decoded) > maxModelBody {
			return nil, true
		}
	}
	rewritten, removed, changed, bad := rewriteTools(decoded, allow)
	if bad {
		return nil, true
	}
	if strings.TrimSpace(r.Header.Get("Content-Encoding")) != "" {
		r.Header.Del("Content-Encoding")
	}
	if changed {
		restoreBody(r, rewritten)
		return uniqueToolTypes(removed), false
	}
	if len(encs) > 0 {
		restoreBody(r, decoded)
		return nil, false
	}
	restoreBody(r, raw)
	return nil, false
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

// rewriteTools returns the body to forward. changed is false when the
// decoded bytes can be forwarded as they arrived. bad refuses the request.
func rewriteTools(body []byte, allow []string) (out []byte, removed []string, changed, bad bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil, false, false
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return nil, nil, false, true
	}
	raw, ok := top["tools"]
	if !ok || len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil, false, false
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, nil, false, true
	}
	allowSet := map[string]bool{}
	for _, name := range normalizeAllow(allow) {
		allowSet[name] = true
	}
	var kept []json.RawMessage
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
		return nil, nil, false, false
	}
	if len(kept) == 0 {
		delete(top, "tools")
	} else {
		top["tools"] = marshalRawArray(kept)
	}
	removedSet := map[string]bool{}
	for _, name := range gone {
		removedSet[name] = true
	}
	adjustToolChoice(top, removedSet, len(kept) > 0)
	encoded, err := marshalTop(top)
	if err != nil {
		return nil, nil, false, true
	}
	return encoded, gone, true, false
}

// marshalTop writes the object without HTML escaping, so a kept tool
// entry stays as it was decoded.
func marshalTop(top map[string]json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(top); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

const (
	toolDrop = iota
	toolKeepFunction
	toolKeepAllowed
)

func toolEntryType(entry json.RawMessage) (string, int) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(entry, &obj); err != nil || obj == nil {
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

func jsonTypeName(raw json.RawMessage) (string, bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
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

func marshalRawArray(items []json.RawMessage) json.RawMessage {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(bytes.TrimSpace(item))
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// adjustToolChoice drops a choice that names a removed type, or that
// requires a tool after the tools list is gone. When tools remain, a
// choice that named a removed type becomes "auto".
func adjustToolChoice(top map[string]json.RawMessage, removed map[string]bool, toolsLeft bool) {
	raw, ok := top["tool_choice"]
	if !ok {
		return
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		if !toolsLeft {
			delete(top, "tool_choice")
		}
		return
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		low := strings.ToLower(s)
		if removed[low] || (low == "required" && !toolsLeft) {
			neutralizeChoice(top, toolsLeft)
		}
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil || obj == nil {
		neutralizeChoice(top, toolsLeft)
		return
	}
	if choicePointsAt(obj, removed) || (choiceIsRequired(obj) && !toolsLeft) {
		neutralizeChoice(top, toolsLeft)
	}
}

func neutralizeChoice(top map[string]json.RawMessage, toolsLeft bool) {
	if toolsLeft {
		top["tool_choice"] = json.RawMessage(`"auto"`)
		return
	}
	delete(top, "tool_choice")
}

func choiceIsRequired(obj map[string]json.RawMessage) bool {
	typ, ok := jsonTypeName(obj["type"])
	if ok && typ == "required" {
		return true
	}
	mode, ok := jsonTypeName(obj["mode"])
	return ok && mode == "required" && !okType(obj, "function")
}

func okType(obj map[string]json.RawMessage, want string) bool {
	typ, ok := jsonTypeName(obj["type"])
	return ok && typ == want
}

func choicePointsAt(obj map[string]json.RawMessage, removed map[string]bool) bool {
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
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return true
	}
	for _, el := range arr {
		var one map[string]json.RawMessage
		if json.Unmarshal(el, &one) != nil || one == nil {
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
