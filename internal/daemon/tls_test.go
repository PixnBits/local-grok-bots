package daemon

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func assertOwnerMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if os.FileMode(st.Mode).Perm() != mode {
		t.Fatalf("%s mode %o", path, os.FileMode(st.Mode).Perm())
	}
	if st.Uid != uint32(os.Geteuid()) {
		t.Fatalf("%s uid %d", path, st.Uid)
	}
}

func TestGenerateSelfSignedModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "tls", "cert.pem"), filepath.Join(dir, "tls", "key.pem")
	if err := GenerateSelfSigned(cert, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
	assertOwnerMode(t, cert, 0o600)
	assertOwnerMode(t, key, 0o600)
}

func TestSelfSignedFilesReused(t *testing.T) {
	app := newApp(t, "", nil)
	app.cfg.TLSCert = "/no/such/cert.pem"
	if _, _, err := app.tlsFiles(); err == nil {
		t.Fatal("half-configured TLS must error")
	}
	app.cfg.TLSCert = ""
	app.cfg.TLSKey = ""
	if c, _, err := app.tlsFiles(); err != nil || c != "" {
		t.Fatalf("plain: %q %v", c, err)
	}
	app.cfg.TLSSelfSigned = true
	cert, key, err := app.tlsFiles()
	if err != nil || cert == "" {
		t.Fatalf("self-signed: %q %v", cert, err)
	}
	assertOwnerMode(t, cert, 0o600)
	assertOwnerMode(t, key, 0o600)
	cert2, _, err := app.tlsFiles()
	if err != nil || cert2 != cert {
		t.Fatalf("reuse %q %v", cert2, err)
	}
}

func TestServeTLSUsesProvidedListener(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := GenerateSelfSigned(cert, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveOnListener(srv, ln, cert, key)
	}()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	res, err := client.Get("https://" + addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.TLS == nil || res.TLS.ServerName == "" && len(res.TLS.PeerCertificates) == 0 {
		t.Fatal("response was not TLS")
	}
	_ = srv.Close()
	<-errCh
}
