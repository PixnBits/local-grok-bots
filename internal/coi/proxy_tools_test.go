package coi

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type upSnap struct {
	body   string
	clen   int64
	enc    string
	hdrLen string
}

type stripRec struct {
	bot, run, path, source string
	removed                []string
}

type stripProxy struct {
	t       *testing.T
	eg      *Egress
	base    string
	mu      sync.Mutex
	ups     []upSnap
	strips  []stripRec
	refuses []string
}

func newStripProxy(t *testing.T) *stripProxy {
	t.Helper()
	return newStripProxyAt(t, nil)
}

func newStripProxyAt(t *testing.T, prefixes []string) *stripProxy {
	t.Helper()
	p := &stripProxy{t: t}
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			body = string(b)
		}
		p.mu.Lock()
		p.ups = append(p.ups, upSnap{
			body:   body,
			clen:   r.ContentLength,
			enc:    r.Header.Get("Content-Encoding"),
			hdrLen: r.Header.Get("Content-Length"),
		})
		p.mu.Unlock()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	eg, err := StartLoopback([]string{GrokChatHost}, prefixes, func() (string, error) {
		return "real-token-value", nil
	}, trip)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eg.Close() })
	eg.SetStripAudit(func(botID, runID, path string, removed []string, source string) {
		p.mu.Lock()
		p.strips = append(p.strips, stripRec{bot: botID, run: runID, path: path, source: source, removed: append([]string(nil), removed...)})
		p.mu.Unlock()
	})
	eg.SetRefuseAudit(func(botID, runID, path, reason string) {
		if botID != "bot-a" || runID != "run-1" {
			t.Errorf("refuse route %s %s %s", botID, runID, path)
		}
		p.mu.Lock()
		p.refuses = append(p.refuses, reason+" "+path)
		p.mu.Unlock()
	})
	p.eg = eg
	p.base = eg.Base()
	return p
}

func (p *stripProxy) reset() {
	p.t.Helper()
	p.mu.Lock()
	p.ups = nil
	p.strips = nil
	p.refuses = nil
	p.mu.Unlock()
}

func (p *stripProxy) post(route, body, auth string, hdr map[string]string) int {
	p.t.Helper()
	return p.send(http.MethodPost, route, []byte(body), auth, hdr)
}

func (p *stripProxy) send(method, route string, body []byte, auth string, hdr map[string]string) int {
	p.t.Helper()
	req, err := http.NewRequest(method, p.base+route, bytes.NewReader(body))
	if err != nil {
		p.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(respBody), "planted-phrase") || strings.Contains(string(respBody), "do-not-audit-this-payload") {
		p.t.Fatalf("response carried request text: %s", respBody)
	}
	return resp.StatusCode
}

func (p *stripProxy) postBytes(route string, body []byte, auth string, hdr map[string]string) int {
	p.t.Helper()
	return p.send(http.MethodPost, route, body, auth, hdr)
}

func (p *stripProxy) lastUp() upSnap {
	p.t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.ups) == 0 {
		p.t.Fatal("no upstream request")
	}
	return p.ups[len(p.ups)-1]
}

func (p *stripProxy) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ups)
}

func gzipBytes(t *testing.T, raw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T, raw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func flateBytes(t *testing.T, raw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProxyStripsNonFunctionTools(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.Admit("bot-a", "run-1", gate)
	defer stop()
	route := "/bots/bot-a/runs/run-1/v1/responses"
	secret := `{"input":"planted-phrase","tools":[{"type":"web_search","description":"do-not-audit-this-payload"},{"type":"x_search"},{"type":"function","name":"read_file"}]}`
	if p.post(route, secret, gate, nil) != http.StatusOK || p.calls() != 1 {
		t.Fatalf("strip status calls %d", p.calls())
	}
	up := p.lastUp()
	if strings.Contains(up.body, "web_search") || strings.Contains(up.body, "x_search") || strings.Contains(up.body, "do-not-audit-this-payload") {
		t.Fatalf("upstream kept a server tool: %s", up.body)
	}
	if !strings.Contains(up.body, "planted-phrase") || !strings.Contains(up.body, `"type":"function"`) {
		t.Fatalf("upstream dropped the rest: %s", up.body)
	}
	if up.clen != int64(len(up.body)) || up.hdrLen != strconv.Itoa(len(up.body)) || up.enc != "" {
		t.Fatalf("length enc %#v", up)
	}
	p.mu.Lock()
	strips := append([]stripRec(nil), p.strips...)
	p.mu.Unlock()
	if len(strips) != 1 || strips[0].bot != "bot-a" || strips[0].run != "run-1" || strips[0].path != "/v1/responses" || strips[0].source != "no_net" {
		t.Fatalf("strip %#v", strips)
	}
	if strings.Join(strips[0].removed, ",") != "web_search,x_search" {
		t.Fatalf("removed %#v", strips[0].removed)
	}
	joined := strips[0].bot + strips[0].path + strips[0].source + strings.Join(strips[0].removed, ",")
	if strings.Contains(joined, "planted-phrase") || strings.Contains(joined, "do-not-audit") {
		t.Fatalf("audit carried body text %s", joined)
	}

	fnBody := `{"tools": [ {"type": "function", "name": "read_file"} ]}`
	fnKept := `{"tools":[{"name":"read_file","type":"function"}]}`
	if p.post(route, fnBody, gate, nil) != http.StatusOK {
		t.Fatal("function")
	}
	if got := p.lastUp().body; got != fnKept {
		t.Fatalf("function body %q", got)
	}
	p.mu.Lock()
	if len(p.strips) != 1 {
		t.Fatalf("function listed a strip %#v", p.strips)
	}
	p.mu.Unlock()

	plain := `{"input":"hi"}`
	if p.post(route, plain, gate, nil) != http.StatusOK || p.lastUp().body != plain {
		t.Fatalf("no tools %q", p.lastUp().body)
	}
	empty := `{"tools":[]}`
	if p.post(route, empty, gate, nil) != http.StatusOK || p.lastUp().body != empty {
		t.Fatalf("empty tools %q", p.lastUp().body)
	}
	nullTools := `{"tools":null,"input":"hi"}`
	if p.post(route, nullTools, gate, nil) != http.StatusOK || p.lastUp().body != `{"input":"hi","tools":null}` {
		t.Fatalf("null tools %q", p.lastUp().body)
	}

	before := p.calls()
	if p.post(route, `not-json`, gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("invalid json")
	}
	if p.post(route, `{"tools":{"type":"web_search"}}`, gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("tools object")
	}
	if p.post(route, `{"input":"planted-phrase","tools":`, gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("truncated")
	}
	p.mu.Lock()
	refuses := append([]string(nil), p.refuses...)
	p.mu.Unlock()
	if len(refuses) != 3 {
		t.Fatalf("refuses %#v", refuses)
	}
	for _, r := range refuses {
		if !strings.HasPrefix(r, "unparsed ") || strings.Contains(r, "planted-phrase") || strings.Contains(r, "web_search") {
			t.Fatalf("refuse %q", r)
		}
	}

	chat := "/bots/bot-a/runs/run-1/v1/chat/completions"
	if p.post(chat, `{"tools":[{"type":"web_search"}]}`, gate, nil) != http.StatusOK || strings.Contains(p.lastUp().body, "web_search") {
		t.Fatalf("chat %s", p.lastUp().body)
	}
	req, err := http.NewRequest(http.MethodGet, p.base+route, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+gate)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %d", resp.StatusCode)
	}

	var consulted bool
	p.eg.SetServerTools(func(botID string) ([]string, string) {
		consulted = true
		if botID != "bot-a" {
			t.Errorf("bot %s", botID)
		}
		return []string{"web_search", "x_search"}, "managed"
	})
	p.reset()
	if p.post(route, secret, gate, nil) != http.StatusOK || consulted {
		t.Fatal("no-net consulted the allow list")
	}
	if strings.Contains(p.lastUp().body, "web_search") || strings.Contains(p.lastUp().body, "x_search") {
		t.Fatalf("no-net kept a server tool: %s", p.lastUp().body)
	}
	p.mu.Lock()
	if len(p.strips) != 1 || p.strips[0].source != "no_net" {
		t.Fatalf("no-net strip %#v", p.strips)
	}
	p.mu.Unlock()

	stop()
	const granted = "unit-loopback-gate2"
	stopNet := p.eg.AdmitNet("bot-a", "run-1", granted, true)
	defer stopNet()
	p.eg.SetServerTools(nil)
	p.reset()
	if p.post(route, `{"tools":[{"type":"web_search"},{"type":"function","name":"read_file"}]}`, granted, nil) != http.StatusOK {
		t.Fatal("default deny")
	}
	if strings.Contains(p.lastUp().body, "web_search") || !strings.Contains(p.lastUp().body, "read_file") {
		t.Fatalf("default deny body %s", p.lastUp().body)
	}
	p.mu.Lock()
	if len(p.strips) != 1 || p.strips[0].source != "default" || strings.Join(p.strips[0].removed, ",") != "web_search" {
		t.Fatalf("default strip %#v", p.strips)
	}
	p.mu.Unlock()

	p.eg.SetServerTools(func(string) ([]string, string) {
		return []string{"web_search"}, "managed"
	})
	p.reset()
	mixed := `{"n":2,"tools":[{"type":"web_search","foo":1},{"type":"x_search"},{"type":"function","name":"a&b"}]}`
	if p.post(route, mixed, granted, nil) != http.StatusOK {
		t.Fatal("allow")
	}
	got := p.lastUp().body
	want := `{"n":2,"tools":[{"foo":1,"type":"web_search"},{"name":"a&b","type":"function"}]}`
	if got != want {
		t.Fatalf("kept %s", got)
	}
	if strings.Contains(got, `\u0026`) || strings.Contains(got, "x_search") {
		t.Fatalf("rewritten %s", got)
	}
	p.mu.Lock()
	if len(p.strips) != 1 || p.strips[0].source != "managed" || strings.Join(p.strips[0].removed, ",") != "x_search" {
		t.Fatalf("allow strip %#v", p.strips)
	}
	p.mu.Unlock()

	p.reset()
	if p.post(route, `{"tools":[{"type":"web_search"},{"type":"Web_Search"}]}`, granted, nil) != http.StatusOK {
		t.Fatal("dup")
	}
	p.mu.Lock()
	if len(p.strips) != 0 {
		t.Fatalf("allowed type audited %#v", p.strips)
	}
	p.mu.Unlock()
	if !strings.Contains(p.lastUp().body, "web_search") {
		t.Fatalf("allowed type dropped %s", p.lastUp().body)
	}

	p.eg.SetServerTools(func(string) ([]string, string) {
		return []string{"web_search"}, "no_net"
	})
	p.reset()
	if p.post(route, `{"tools":[{"type":"web_search"}]}`, granted, nil) != http.StatusOK || strings.Contains(p.lastUp().body, "web_search") {
		t.Fatalf("unknown source kept a tool %s", p.lastUp().body)
	}
	p.mu.Lock()
	if len(p.strips) != 1 || p.strips[0].source != "default" {
		t.Fatalf("unknown source %#v", p.strips)
	}
	p.mu.Unlock()
}

func TestProxyToolChoiceCleanup(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.AdmitNet("bot-a", "run-1", gate, true)
	defer stop()
	p.eg.SetServerTools(func(string) ([]string, string) {
		return nil, "default"
	})
	route := "/bots/bot-a/runs/run-1/v1/responses"
	cases := []struct {
		body string
		want string
	}{
		{
			`{"tools":[{"type":"function","name":"read_file"},{"type":"web_search"}],"tool_choice":"web_search"}`,
			`{"tool_choice":"auto","tools":[{"name":"read_file","type":"function"}]}`,
		},
		{
			`{"input":"hi","tools":[{"type":"web_search"}],"tool_choice":"required"}`,
			`{"input":"hi"}`,
		},
		{
			`{"tools":[{"type":"web_search"}],"tool_choice":{"type":"web_search"}}`,
			`{}`,
		},
		{
			`{"tools":[{"type":"function","name":"read_file"},{"type":"web_search"}],"tool_choice":"required"}`,
			`{"tool_choice":"required","tools":[{"name":"read_file","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"function","name":"read_file"},{"type":"web_search"}],"tool_choice":{"type":"function","name":"read_file"}}`,
			`{"tool_choice":{"name":"read_file","type":"function"},"tools":[{"name":"read_file","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"function","name":"web_search"},{"type":"web_search"}],"tool_choice":{"type":"function","name":"web_search"}}`,
			`{"tool_choice":"auto","tools":[{"name":"web_search","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"function","name":"a"},{"type":"web_search"}],"tool_choice":{"type":"allowed_tools","tools":[{"type":"web_search"}]}}`,
			`{"tool_choice":"auto","tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"web_search"},{"type":"function","name":"a"}],"tool_choice":"auto"}`,
			`{"tool_choice":"auto","tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"web_search"},{"type":"function","name":"a"}],"tool_choice":"none"}`,
			`{"tool_choice":"none","tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"function","name":"a"},{"type":"web_search"}],"tool_choice":{"type":"required"}}`,
			`{"tool_choice":{"type":"required"},"tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"web_search"}],"tool_choice":{"type":"required"}}`,
			`{}`,
		},
		{
			`{"tools":[{"type":"web_search"}],"tool_choice":1}`,
			`{}`,
		},
		{
			`{"input":"hi","tools":["nope",{"type":"function","name":"a"}]}`,
			`{"input":"hi","tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{"type":"code_interpreter"}]}`,
			`{}`,
		},
		{
			`{"tools":[{"type":1},{"type":"function","name":"a"}]}`,
			`{"tools":[{"name":"a","type":"function"}]}`,
		},
		{
			`{"tools":[{}]}`,
			`{}`,
		},
	}
	for _, tc := range cases {
		p.reset()
		if p.post(route, tc.body, gate, nil) != http.StatusOK {
			t.Fatalf("status for %s", tc.body)
		}
		if got := p.lastUp().body; got != tc.want {
			t.Fatalf("body %s\ngot  %s\nwant %s", tc.body, got, tc.want)
		}
		p.mu.Lock()
		removed := ""
		if len(p.strips) == 1 {
			removed = strings.Join(p.strips[0].removed, ",")
		}
		p.mu.Unlock()
		if strings.Contains(removed, "{") || strings.Contains(removed, "nope") || strings.Contains(removed, "description") {
			t.Fatalf("removed %q", removed)
		}
	}
	p.reset()
	if p.post(route, `{"tools":[{}]}`, gate, nil) != http.StatusOK {
		t.Fatal("invalid entry")
	}
	p.mu.Lock()
	if len(p.strips) != 1 || strings.Join(p.strips[0].removed, ",") != "invalid" {
		t.Fatalf("invalid audit %#v", p.strips)
	}
	p.mu.Unlock()
}

func TestProxyStripsCompressedBodies(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.AdmitNet("bot-a", "run-1", gate, true)
	defer stop()
	p.eg.SetServerTools(func(string) ([]string, string) {
		return []string{"web_search"}, "local"
	})
	route := "/bots/bot-a/runs/run-1/v1/responses"
	raw := `{"tools":[{"type":"function","name":"read_file"},{"type":"x_search"}]}`
	kept := `{"tools":[{"name":"read_file","type":"function"}]}`
	fnOnly := `{"tools":[{"type":"function","name":"read_file"}]}`

	check := func(enc string, body []byte, want string) {
		t.Helper()
		p.reset()
		if p.postBytes(route, body, gate, map[string]string{"Content-Encoding": enc}) != http.StatusOK {
			t.Fatalf("%s status", enc)
		}
		up := p.lastUp()
		if up.body != want || up.enc != "" || up.clen != int64(len(want)) || up.hdrLen != strconv.Itoa(len(want)) {
			t.Fatalf("%s up %#v", enc, up)
		}
	}
	check("gzip", gzipBytes(t, raw), kept)
	check("x-gzip", gzipBytes(t, raw), kept)
	check("deflate", zlibBytes(t, raw), kept)
	check("deflate", flateBytes(t, raw), kept)
	check("gzip", gzipBytes(t, fnOnly), kept)

	outer := gzipBytes(t, string(flateBytes(t, raw)))
	check("deflate, gzip", outer, kept)

	before := p.calls()
	for _, enc := range []string{"br", "zstd", "gzip;q=1", "compress"} {
		if p.postBytes(route, gzipBytes(t, raw), gate, map[string]string{"Content-Encoding": enc}) != http.StatusForbidden || p.calls() != before {
			t.Fatalf("%s was forwarded", enc)
		}
	}
	p.mu.Lock()
	if len(p.refuses) != 4 {
		t.Fatalf("refuses %#v", p.refuses)
	}
	for _, r := range p.refuses {
		if !strings.HasPrefix(r, "unparsed ") {
			t.Fatalf("refuse %q", r)
		}
	}
	p.mu.Unlock()

	trunc := gzipBytes(t, raw)
	trunc = trunc[:len(trunc)-3]
	if p.postBytes(route, trunc, gate, map[string]string{"Content-Encoding": "gzip"}) != http.StatusForbidden || p.calls() != before {
		t.Fatal("truncated gzip")
	}
}

func TestEgressDoesNotStripServerTools(t *testing.T) {
	var got string
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	eg, err := StartEgress(t.TempDir(), []string{"api.test"}, nil, "real-token-value", trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", eg.Sock())
		},
	}
	client := &http.Client{Transport: tr}
	const body = `{"tools":[{"type":"web_search"}]}`
	req, err := http.NewRequest(http.MethodPost, "http://localhost/v1/responses", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || got != body {
		t.Fatalf("status %d body %q", resp.StatusCode, got)
	}
}

func TestProxyRefusesDuplicateKeys(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.AdmitNet("bot-a", "run-1", gate, true)
	defer stop()
	p.eg.SetServerTools(func(string) ([]string, string) {
		t.Fatal("duplicate key consulted the allow list")
		return []string{"web_search"}, "managed"
	})
	route := "/bots/bot-a/runs/run-1/v1/responses"
	cases := []struct {
		name string
		body string
	}{
		{"top", `{"tools":[{"type":"function","name":"read_file"}],"input":"planted-phrase","tools":[{"type":"web_search"}]}`},
		{"nested", `{"tools":[{"type":"web_search","type":"function","name":"do-not-audit-this-payload"}]}`},
		{"choice", `{"tool_choice":{"type":"function","type":"web_search"},"input":"hi"}`},
		{"escaped", `{"tools":[{"type":"function","ty\u0070e":"web_search","name":"a"}]}`},
	}
	for _, tc := range cases {
		p.reset()
		before := p.calls()
		if p.post(route, tc.body, gate, nil) != http.StatusForbidden || p.calls() != before {
			t.Fatalf("%s forwarded", tc.name)
		}
		p.mu.Lock()
		refuses := append([]string(nil), p.refuses...)
		strips := len(p.strips)
		p.mu.Unlock()
		if strips != 0 || len(refuses) != 1 || !strings.HasPrefix(refuses[0], "duplicate_key ") {
			t.Fatalf("%s audit %#v strips %d", tc.name, refuses, strips)
		}
		if strings.Contains(refuses[0], "planted-phrase") || strings.Contains(refuses[0], "web_search") || strings.Contains(refuses[0], "do-not-audit") {
			t.Fatalf("%s audit carried body %s", tc.name, refuses[0])
		}
	}
}

func TestProxyRemarshalsUnchangedBody(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.Admit("bot-a", "run-1", gate)
	defer stop()
	route := "/bots/bot-a/runs/run-1/v1/responses"
	orig := "{\n  \"z\" : 1,\n  \"a\" : \"x<y&z\",\n  \"n\" : 9007199254740993\n}\n"
	want := `{"a":"x<y&z","n":9007199254740993,"z":1}`
	if p.post(route, orig, gate, nil) != http.StatusOK {
		t.Fatal("status")
	}
	up := p.lastUp()
	if up.body == orig || up.body != want || up.clen != int64(len(want)) || up.hdrLen != strconv.Itoa(len(want)) || up.enc != "" {
		t.Fatalf("upstream %#v", up)
	}
	if strings.Contains(up.body, `\u003c`) || strings.Contains(up.body, `\u0026`) {
		t.Fatalf("escaped %s", up.body)
	}
	p.mu.Lock()
	if len(p.strips) != 0 || len(p.refuses) != 0 {
		t.Fatalf("audited a clean body strips %#v refuses %#v", p.strips, p.refuses)
	}
	p.mu.Unlock()
}

func TestProxyFiltersToolsOnAnyPath(t *testing.T) {
	p := newStripProxy(t)
	const gate = "unit-loopback-gate1"
	stop := p.eg.Admit("bot-a", "run-1", gate)
	defer stop()
	body := `{"tools":[{"type":"web_search"},{"type":"x_search"},{"type":"function","name":"read_file"}]}`
	want := `{"tools":[{"name":"read_file","type":"function"}]}`
	paths := []struct {
		route string
		audit string
	}{
		{"/bots/bot-a/runs/run-1/v1/responses/x", "/v1/responses/x"},
		{"/bots/bot-a/runs/run-1/v1/responses:stream", "/v1/responses:stream"},
		{"/bots/bot-a/runs/run-1/v1/responses/", "/v1/responses"},
		{"/bots/bot-a/runs/run-1/v1/RESPONSES/x", "/v1/RESPONSES/x"},
		{"/bots/bot-a/runs/run-1/v1/chat/completions/extra", "/v1/chat/completions/extra"},
		{"/bots/bot-a/runs/run-1/v1/ping", "/v1/ping"},
	}
	for _, tc := range paths {
		p.reset()
		if p.post(tc.route, body, gate, nil) != http.StatusOK {
			t.Fatalf("%s status", tc.route)
		}
		up := p.lastUp()
		if up.body != want || strings.Contains(up.body, "web_search") || strings.Contains(up.body, "x_search") {
			t.Fatalf("%s body %s", tc.route, up.body)
		}
		if up.clen != int64(len(want)) || up.hdrLen != strconv.Itoa(len(want)) {
			t.Fatalf("%s length %#v", tc.route, up)
		}
		p.mu.Lock()
		strips := append([]stripRec(nil), p.strips...)
		p.mu.Unlock()
		if len(strips) != 1 || strips[0].path != tc.audit || strips[0].source != "no_net" || strings.Join(strips[0].removed, ",") != "web_search,x_search" {
			t.Fatalf("%s strip %#v", tc.route, strips)
		}
	}

	p.reset()
	if p.send(http.MethodPut, "/bots/bot-a/runs/run-1/v1/responses/x", []byte(body), gate, nil) != http.StatusOK || p.lastUp().body != want {
		t.Fatalf("put %s", p.lastUp().body)
	}
	p.reset()
	if p.send(http.MethodGet, "/bots/bot-a/runs/run-1/v1/ping", []byte(body), gate, nil) != http.StatusOK || strings.Contains(p.lastUp().body, "web_search") {
		t.Fatalf("get body %s", p.lastUp().body)
	}

	p.reset()
	plain := "{ \"b\" : 1, \"a\" : 2 }"
	if p.post("/bots/bot-a/runs/run-1/v1/ping", plain, gate, nil) != http.StatusOK || p.lastUp().body != `{"a":2,"b":1}` {
		t.Fatalf("no tools %q", p.lastUp().body)
	}
	p.mu.Lock()
	if len(p.strips) != 0 {
		t.Fatalf("plain stripped %#v", p.strips)
	}
	p.mu.Unlock()

	before := p.calls()
	if p.post("/bots/bot-a/runs/run-1/v1/ping", "not-json", gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("non-json forwarded")
	}
	if p.post("/bots/bot-a/runs/run-1/v1/models", "   ", gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("whitespace forwarded")
	}
	deep := strings.Repeat(`{"a":`, maxJSONDepth+1) + "1" + strings.Repeat("}", maxJSONDepth+1)
	if p.post("/bots/bot-a/runs/run-1/v1/ping", deep, gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("deep body forwarded")
	}
	p.mu.Lock()
	refuses := append([]string(nil), p.refuses...)
	p.mu.Unlock()
	if len(refuses) != 3 {
		t.Fatalf("refuses %#v", refuses)
	}
	for _, r := range refuses {
		if !strings.HasPrefix(r, "unparsed ") || strings.Contains(r, "not-json") {
			t.Fatalf("refuse %q", r)
		}
	}

	p.reset()
	before = p.calls()
	if p.post("/bots/bot-a/runs/run-1/v1//responses", body, gate, nil) != http.StatusForbidden || p.calls() != before {
		t.Fatal("double slash forwarded")
	}
	p.mu.Lock()
	if len(p.refuses) != 0 || len(p.strips) != 0 {
		t.Fatalf("double slash filtered %#v %#v", p.refuses, p.strips)
	}
	p.mu.Unlock()

	other := newStripProxyAt(t, []string{"/api"})
	stopAPI := other.eg.Admit("bot-a", "run-1", gate)
	defer stopAPI()
	if other.post("/bots/bot-a/runs/run-1/api/chat", body, gate, nil) != http.StatusOK || strings.Contains(other.lastUp().body, "web_search") {
		t.Fatalf("non-v1 %s", other.lastUp().body)
	}
	other.mu.Lock()
	if len(other.strips) != 1 || other.strips[0].path != "/api/chat" || other.strips[0].source != "no_net" {
		t.Fatalf("non-v1 strip %#v", other.strips)
	}
	other.mu.Unlock()
	if other.post("/bots/bot-a/runs/run-1/api/chat", "not-json", gate, nil) != http.StatusForbidden || other.calls() != 1 {
		t.Fatal("non-v1 non-json forwarded")
	}
}
