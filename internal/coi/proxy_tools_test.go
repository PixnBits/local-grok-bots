package coi

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProxyRefusesNonFunctionTools(t *testing.T) {
	var calls atomic.Int32
	var gotBody string
	trip := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	eg, err := StartLoopback([]string{GrokChatHost}, nil, func() (string, error) {
		return "real-token-value", nil
	}, trip)
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close()
	var reasons []string
	eg.SetRefuseAudit(func(botID, runID, path, reason string) {
		if botID != "bot-a" || runID != "run-1" {
			t.Errorf("route %s %s", botID, runID)
		}
		if strings.Contains(reason, "{") || strings.Contains(reason, "web_search") || strings.Contains(reason, "x_search") {
			t.Errorf("reason %q", reason)
		}
		reasons = append(reasons, reason+" "+path)
	})
	const gate = "unit-loopback-gate1"
	stop := eg.Admit("bot-a", "run-1", gate)
	defer stop()
	base := eg.Base()
	post := func(route, body, auth string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, base+route, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(respBody), "web_search") || strings.Contains(string(respBody), "x_search") {
			t.Fatalf("response carried a tool name: %s", respBody)
		}
		return resp.StatusCode
	}
	respRoute := "/bots/bot-a/runs/run-1/v1/responses"
	if post(respRoute, `{"tools":[{"type":"web_search"}]}`, gate) != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("web_search status calls %d", calls.Load())
	}
	if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "server_tool ") || !strings.Contains(reasons[0], "/v1/responses") {
		t.Fatal(reasons)
	}
	if post(respRoute, `{"tools":[{"type":"x_search"}]}`, gate) != http.StatusForbidden || calls.Load() != 0 {
		t.Fatal("x_search")
	}
	if post(respRoute, `{"tools":[{"type":"function","name":"read_file"},{"type":"web_search"}]}`, gate) != http.StatusForbidden {
		t.Fatal("mixed")
	}
	fnBody := `{"tools":[{"type":"function","name":"read_file"}]}`
	if post(respRoute, fnBody, gate) != http.StatusOK || calls.Load() != 1 || !strings.Contains(gotBody, `"type":"function"`) {
		t.Fatalf("function body %q calls %d", gotBody, calls.Load())
	}
	if post(respRoute, `{"input":"hi"}`, gate) != http.StatusOK || calls.Load() != 2 {
		t.Fatal("no tools")
	}
	if post(respRoute, `{"tools":[]}`, gate) != http.StatusOK {
		t.Fatal("empty tools")
	}
	if post(respRoute, `{oops "tools": [`, gate) != http.StatusForbidden {
		t.Fatal("unparsed")
	}
	if !strings.HasPrefix(reasons[len(reasons)-1], "unparsed ") {
		t.Fatal(reasons)
	}
	before := calls.Load()
	if post(respRoute, `not-json`, gate) != http.StatusOK || calls.Load() != before+1 {
		t.Fatal("unparsed without tools")
	}
	chat := "/bots/bot-a/runs/run-1/v1/chat/completions"
	if post(chat, `{"tools":[{"type":"web_search"}]}`, gate) != http.StatusForbidden || calls.Load() != before+1 {
		t.Fatal("chat")
	}
	req, err := http.NewRequest(http.MethodGet, base+respRoute, nil)
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
	stop()
	const granted = "unit-loopback-gate2"
	stopNet := eg.AdmitNet("bot-a", "run-1", granted, true)
	defer stopNet()
	n := calls.Load()
	nReasons := len(reasons)
	if post(respRoute, `{"tools":[{"type":"web_search"},{"type":"x_search"}]}`, granted) != http.StatusOK || calls.Load() != n+1 {
		t.Fatalf("net grant calls %d", calls.Load())
	}
	if len(reasons) != nReasons {
		t.Fatal(reasons)
	}
}
