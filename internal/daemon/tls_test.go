package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	if err := GenerateSelfSigned(cert, key, time.Now(), ""); err != nil {
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
	if err := GenerateSelfSigned(cert, key, time.Now(), ""); err != nil {
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

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSelfSignedSANs(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := GenerateSelfSigned(cert, key, time.Now(), "192.0.2.10:8443"); err != nil {
		t.Fatal(err)
	}
	got := loadCert(t, cert)
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "localhost" {
		t.Fatalf("dns %v", got.DNSNames)
	}
	want := map[string]bool{"127.0.0.1": true, "::1": true, "192.0.2.10": true}
	if len(got.IPAddresses) != len(want) {
		t.Fatalf("ips %v", got.IPAddresses)
	}
	for _, ip := range got.IPAddresses {
		if !want[ip.String()] {
			t.Fatalf("unexpected ip %s", ip)
		}
	}
	host, _ := os.Hostname()
	for _, name := range got.DNSNames {
		if host != "" && host != "localhost" && name == host {
			t.Fatalf("hostname %s in cert", host)
		}
	}

	wild, wildKey := filepath.Join(dir, "wild.pem"), filepath.Join(dir, "wild.key")
	if err := GenerateSelfSigned(wild, wildKey, time.Now(), "0.0.0.0:443"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range loadCert(t, wild).IPAddresses {
		if ip.IsUnspecified() || ip.String() == "0.0.0.0" {
			t.Fatalf("wildcard ip %s", ip)
		}
	}
	v6, v6Key := filepath.Join(dir, "v6.pem"), filepath.Join(dir, "v6.key")
	if err := GenerateSelfSigned(v6, v6Key, time.Now(), "[::]:443"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range loadCert(t, v6).IPAddresses {
		if ip.IsUnspecified() {
			t.Fatalf("wildcard ip %s", ip)
		}
	}
}

func TestSelfSignedRenewsWhenSoon(t *testing.T) {
	app := newApp(t, "", nil)
	app.cfg.TLSSelfSigned = true
	cert := filepath.Join(app.cfg.DataDir, "tls", "cert.pem")
	key := filepath.Join(app.cfg.DataDir, "tls", "key.pem")
	old := time.Now().Add(-340 * 24 * time.Hour)
	if err := GenerateSelfSigned(cert, key, old, app.cfg.BindAddr); err != nil {
		t.Fatal(err)
	}
	before := loadCert(t, cert).SerialNumber.String()
	got, _, err := app.tlsFiles()
	if err != nil || got != cert {
		t.Fatalf("renew %q %v", got, err)
	}
	if loadCert(t, cert).SerialNumber.String() == before {
		t.Fatal("soon cert was reused")
	}
	assertOwnerMode(t, cert, 0o600)
	assertOwnerMode(t, key, 0o600)

	if err := os.WriteFile(cert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatal(err)
	}
}

func TestSelfSignedReuseSkipsSymlink(t *testing.T) {
	app := newApp(t, "", nil)
	app.cfg.TLSSelfSigned = true
	dir := filepath.Join(app.cfg.DataDir, "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	realKey := filepath.Join(app.cfg.DataDir, "real.key")
	if err := os.WriteFile(realKey, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	realCert := filepath.Join(app.cfg.DataDir, "real.crt")
	if err := os.WriteFile(realCert, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realCert, filepath.Join(dir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realKey, filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(realKey)
	if err != nil || string(b) != "keep" {
		t.Fatalf("target changed %q %v", b, err)
	}
	assertOwnerMode(t, filepath.Join(dir, "key.pem"), 0o600)
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, "key.pem"), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		t.Fatal("key is still a symlink")
	}
}

func TestSuppliedTLSKeyRefused(t *testing.T) {
	app := newApp(t, "", nil)
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.pem")
	if err := os.WriteFile(real, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key.pem")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	app.cfg.TLSCert = cert
	app.cfg.TLSKey = link
	if _, _, err := app.tlsFiles(); err == nil || !strings.Contains(err.Error(), "TLS_KEY") {
		t.Fatalf("symlink %v", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := app.tlsFiles(); err == nil || !strings.Contains(err.Error(), "TLS_KEY") || !strings.Contains(err.Error(), "readable") {
		t.Fatalf("mode %v", err)
	}
	if err := os.Chmod(link, 0o600); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey, err := app.tlsFiles()
	if err != nil || gotCert != cert || gotKey != link {
		t.Fatalf("files %q %q %v", gotCert, gotKey, err)
	}
}

func TestListeningAfterTLS(t *testing.T) {
	app := newApp(t, "", nil)
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(key, []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.cfg.TLSCert = cert
	app.cfg.TLSKey = key
	buf := &safeBuf{}
	app.logw = buf
	err := app.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "TLS_KEY") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(buf.String(), "listening on") {
		t.Fatalf("logged listen before tls: %s", buf.String())
	}
}
