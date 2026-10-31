package daemon

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const csrfCrossOrigin = "http://192.0.2.10:9999"

func TestMutatingAPICrossOriginForbidden(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	bot := createBot(t, srv.URL, "Ada")
	tok := armAdmin(app)
	routes := []struct{ method, path string }{
		{"POST", "/api/bots/" + bot.ID + "/runs/r1/permissions/q1"},
		{"POST", "/api/bots/" + bot.ID + "/permission-rules"},
		{"DELETE", "/api/bots/" + bot.ID + "/permission-rules/r1"},
		{"POST", "/api/bots/" + bot.ID + "/permission-suggestions/s1/accept"},
		{"POST", "/api/bots/" + bot.ID + "/permission-suggestions/s1/dismiss"},
		{"POST", "/api/bots"},
	}
	for _, rt := range routes {
		req, err := http.NewRequest(rt.method, srv.URL+rt.path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = req.URL.Host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Origin", csrfCrossOrigin)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s %d %s", rt.method, rt.path, res.StatusCode, body)
		}
	}
}

func TestMutatingAPINonJSONContentType(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	tok := armAdmin(app)
	types := []string{
		"text/plain",
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=----x",
	}
	for _, ct := range types {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/bots", strings.NewReader(`{"name":"Ada"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Host = req.URL.Host
		req.Header.Set("Content-Type", ct)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Origin", "http://"+req.URL.Host)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("%s %d %s", ct, res.StatusCode, body)
		}
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/bots", strings.NewReader(`{"name":"Ada"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Origin", "http://"+req.URL.Host)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type %d %s", res.StatusCode, body)
	}
}

func TestMutatingAPISameOriginJSON(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	tok := armAdmin(app)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/bots", strings.NewReader(`{"name":"Ada","description":"p"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Origin", "http://"+req.URL.Host)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnsupportedMediaType {
		t.Fatalf("same-origin json %d %s", res.StatusCode, body)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create %d %s", res.StatusCode, body)
	}
}
