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

	"github.com/PixnBits/local-grok-bots/internal/policy"
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
	if err := GenerateSelfSigned(cert, key, time.Now(), "", nil); err != nil {
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
	if err := GenerateSelfSigned(cert, key, time.Now(), "", nil); err != nil {
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
	if err := GenerateSelfSigned(cert, key, time.Now(), "192.0.2.10:8443", nil); err != nil {
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
	if err := GenerateSelfSigned(wild, wildKey, time.Now(), "0.0.0.0:443", nil); err != nil {
		t.Fatal(err)
	}
	for _, ip := range loadCert(t, wild).IPAddresses {
		if ip.IsUnspecified() || ip.String() == "0.0.0.0" {
			t.Fatalf("wildcard ip %s", ip)
		}
	}
	v6, v6Key := filepath.Join(dir, "v6.pem"), filepath.Join(dir, "v6.key")
	if err := GenerateSelfSigned(v6, v6Key, time.Now(), "[::]:443", nil); err != nil {
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
	if err := GenerateSelfSigned(cert, key, old, app.cfg.BindAddr, nil); err != nil {
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

func assertExactSANs(t *testing.T, cert *x509.Certificate, dns, ips []string) {
	t.Helper()
	gotDNS := map[string]int{}
	for _, n := range cert.DNSNames {
		gotDNS[strings.ToLower(n)]++
	}
	if len(gotDNS) != len(dns) || len(cert.DNSNames) != len(dns) {
		t.Fatalf("dns %v", cert.DNSNames)
	}
	for _, n := range dns {
		if gotDNS[strings.ToLower(n)] != 1 {
			t.Fatalf("dns %v missing %s", cert.DNSNames, n)
		}
	}
	gotIP := map[string]int{}
	for _, ip := range cert.IPAddresses {
		gotIP[ip.String()]++
	}
	if len(gotIP) != len(ips) || len(cert.IPAddresses) != len(ips) {
		t.Fatalf("ips %v", cert.IPAddresses)
	}
	for _, ip := range ips {
		if gotIP[ip] != 1 {
			t.Fatalf("ips %v missing %s", cert.IPAddresses, ip)
		}
	}
}

func selfSignedFromStartup(t *testing.T, bind string, hosts []string) *x509.Certificate {
	t.Helper()
	app := newApp(t, "", nil)
	app.cfg.TLSSelfSigned = true
	app.cfg.BindAddr = bind
	app.startPol.AllowedHosts = append([]string(nil), hosts...)
	cert, _, err := app.tlsFiles()
	if err != nil || cert == "" {
		t.Fatalf("cert %q %v", cert, err)
	}
	return loadCert(t, cert)
}

func TestSelfSignedIncludesAllowedHosts(t *testing.T) {
	hosts := []string{
		"100.64.0.10",
		"2001:db8::10",
		"myhost.tailnet-example.ts.net",
		"100.64.0.10",
		"localhost",
		"127.0.0.1",
		"2001:0db8:0000:0000:0000:0000:0000:0010",
	}
	dns := []string{"localhost", "myhost.tailnet-example.ts.net"}
	withBind := selfSignedFromStartup(t, "192.0.2.10:8080", hosts)
	assertExactSANs(t, withBind, dns, []string{"127.0.0.1", "::1", "192.0.2.10", "100.64.0.10", "2001:db8::10"})
	host, _ := os.Hostname()
	for _, name := range withBind.DNSNames {
		if host != "" && host != "localhost" && strings.EqualFold(name, host) {
			t.Fatalf("hostname %s in cert", host)
		}
	}
	wild := selfSignedFromStartup(t, "0.0.0.0:8080", hosts)
	assertExactSANs(t, wild, dns, []string{"127.0.0.1", "::1", "100.64.0.10", "2001:db8::10"})
	for _, ip := range wild.IPAddresses {
		if ip.IsUnspecified() || ip.String() == "0.0.0.0" || ip.String() == "192.0.2.10" {
			t.Fatalf("bind ip %s", ip)
		}
	}
}

func TestSelfSignedReuseFollowsHostList(t *testing.T) {
	app := newApp(t, "", nil)
	app.cfg.TLSSelfSigned = true
	app.cfg.BindAddr = "192.0.2.10:8080"
	full := []string{"100.64.0.10", "2001:db8::10", "myhost.tailnet-example.ts.net"}
	setHosts := func(hosts []string) {
		t.Helper()
		app.startPol.AllowedHosts = append([]string(nil), hosts...)
	}
	setHosts(full)
	cert, _, err := app.tlsFiles()
	if err != nil || cert == "" {
		t.Fatalf("cert %q %v", cert, err)
	}
	serial := loadCert(t, cert).SerialNumber.String()
	if _, _, err = app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	if got := loadCert(t, cert).SerialNumber.String(); got != serial {
		t.Fatalf("unchanged list rewrote %s", got)
	}
	setHosts([]string{"2001:0db8:0000:0000:0000:0000:0000:0010", "myhost.tailnet-example.ts.net", "100.64.0.10"})
	if _, _, err = app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	if got := loadCert(t, cert).SerialNumber.String(); got != serial {
		t.Fatalf("reordered list rewrote %s", got)
	}
	setHosts([]string{"100.64.0.10", "myhost.tailnet-example.ts.net"})
	if _, _, err = app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	removed := loadCert(t, cert).SerialNumber.String()
	if removed == serial {
		t.Fatal("removed name kept the pair")
	}
	setHosts([]string{"100.64.0.10", "myhost.tailnet-example.ts.net", "2001:db8::10"})
	if _, _, err = app.tlsFiles(); err != nil {
		t.Fatal(err)
	}
	if got := loadCert(t, cert).SerialNumber.String(); got == removed {
		t.Fatal("added name kept the pair")
	}
}

func TestOriginAllowedOnListenerPort(t *testing.T) {
	app := &App{}
	app.cfg.BindAddr = "0.0.0.0:8080"
	app.setPol(policy.Policy{AllowedHosts: []string{
		"100.64.0.10",
		"2001:db8::10",
		"myhost.tailnet-example.ts.net",
	}})
	entries := []string{"100.64.0.10", "[2001:db8::10]", "myhost.tailnet-example.ts.net"}
	for _, entry := range entries {
		host := entry + ":8080"
		if !app.originAllowed(originReq(host, "", false)) {
			t.Fatalf("host %s", host)
		}
		if !app.originAllowed(originReq(host, "http://"+entry+":8080", false)) {
			t.Fatalf("http %s", entry)
		}
		if !app.originAllowed(originReq(host, "https://"+entry+":8080", true)) {
			t.Fatalf("https %s", entry)
		}
		if app.originAllowed(originReq(host, "https://"+entry+":8080", false)) {
			t.Fatalf("https on plain %s", entry)
		}
		if app.originAllowed(originReq(host, "http://"+entry+":8080", true)) {
			t.Fatalf("http on tls %s", entry)
		}
		if app.originAllowed(originReq(entry+":9", "", false)) {
			t.Fatalf("port %s", entry)
		}
	}
	if app.originAllowed(originReq("bad_name!:8080", "http://bad_name!:8080", false)) {
		t.Fatal("accepted bad_name!")
	}
}

func originReq(host, origin string, tlsOn bool) *http.Request {
	r := &http.Request{Host: host, Header: make(http.Header)}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if tlsOn {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}
