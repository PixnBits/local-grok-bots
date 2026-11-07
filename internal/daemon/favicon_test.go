package daemon

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/PixnBits/local-grok-bots/web"
)

func TestFaviconPublicBeforeLogin(t *testing.T) {
	app := newApp(t, "", nil)
	srv := serve(t, app)
	armAdmin(app)
	assets := []struct {
		path, contentType string
		body              []byte
	}{
		{"/favicon.svg", "image/svg+xml", web.FaviconSVG},
		{"/favicon.ico", "image/x-icon", web.FaviconICO},
		{"/apple-touch-icon.png", "image/png", web.AppleTouchIcon},
	}
	for _, a := range assets {
		res, body := do(t, "GET", srv.URL+a.path, nil, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s %d %s", a.path, res.StatusCode, body)
		}
		if ct := res.Header.Get("Content-Type"); ct != a.contentType {
			t.Fatalf("%s Content-Type %q", a.path, ct)
		}
		if res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s nosniff %q", a.path, res.Header.Get("X-Content-Type-Options"))
		}
		if !bytes.Equal(body, a.body) {
			t.Fatalf("%s body mismatch", a.path)
		}
	}
	res, body := do(t, "GET", srv.URL+"/", nil, "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/ %d %s", res.StatusCode, body)
	}
}
