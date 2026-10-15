package daemon

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateSelfSigned(t *testing.T) {
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls", "cert.pem"), filepath.Join(dir, "tls", "key.pem")
	if err := GenerateSelfSigned(c, k, time.Now()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	if len(pair.Certificate) != 1 {
		t.Fatalf("certs %d", len(pair.Certificate))
	}
	fi, _ := os.Stat(k)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %v", fi.Mode().Perm())
	}
}

func TestTLSFilesFailClosedAndSelfSigned(t *testing.T) {
	app := newApp(t, "", nil)
	app.cfg.TLSCert = "/x/cert.pem"
	if _, _, err := app.tlsFiles(); err == nil {
		t.Fatal("half-configured TLS must error")
	}
	app.cfg.TLSCert = ""
	if c, _, err := app.tlsFiles(); err != nil || c != "" {
		t.Fatalf("plain http: %q %v", c, err)
	}
	app.cfg.TLSSelfSigned = true
	c, k, err := app.tlsFiles()
	if err != nil || c == "" {
		t.Fatalf("self-signed: %q %v", c, err)
	}
	c2, _, _ := app.tlsFiles()
	if c2 != c {
		t.Fatal("reuse")
	}
	if _, err := tls.LoadX509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
}
