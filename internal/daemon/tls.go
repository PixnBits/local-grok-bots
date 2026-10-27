package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
	"golang.org/x/sys/unix"
)

// tlsConfigured reports whether the daemon will serve HTTPS.
func tlsConfigured(c config.Config) bool {
	return c.TLSSelfSigned || c.TLSCert != "" || c.TLSKey != ""
}

// serveOnListener serves srv on ln. A cert and key use TLS on that listener.
// An empty pair is plain HTTP. This does not open a second listener.
func serveOnListener(srv *http.Server, ln net.Listener, cert, key string) error {
	if (cert == "") != (key == "") {
		return errors.New("TLS cert and key must be set together")
	}
	if cert != "" {
		return srv.ServeTLS(ln, cert, key)
	}
	return srv.Serve(ln)
}

// tlsFiles returns the cert and key for HTTPS, or empty strings for plain HTTP.
// A half-configured pair is an error.
func (a *App) tlsFiles() (string, string, error) {
	c := a.cfg
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return "", "", errors.New("TLS_CERT and TLS_KEY must be set together")
	}
	if c.TLSCert != "" {
		name := tlsKeySetting(a)
		if err := checkSuppliedTLSKey(c.TLSKey, name); err != nil {
			return "", "", err
		}
		a.log("", "tls_enabled", map[string]any{"mode": "files", "cert": c.TLSCert})
		return c.TLSCert, c.TLSKey, nil
	}
	if !c.TLSSelfSigned {
		return "", "", nil
	}
	dir := filepath.Join(c.DataDir, "tls")
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	now := time.Now()
	if reuse, err := reuseSelfSigned(cert, key, now); err != nil {
		return "", "", err
	} else if reuse {
		a.log("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": false})
		return cert, key, nil
	}
	if err := GenerateSelfSigned(cert, key, now, c.BindAddr); err != nil {
		return "", "", err
	}
	a.log("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": true})
	return cert, key, nil
}

func tlsKeySetting(a *App) string {
	if a == nil {
		return "TLS_KEY"
	}
	pol := a.pol()
	if pol.HasTLS && pol.TLSKey != "" && pol.TLSKey == a.cfg.TLSKey {
		return "tls_key"
	}
	return "TLS_KEY"
}

// checkSuppliedTLSKey refuses a symlink or a key that is group or other readable.
func checkSuppliedTLSKey(path, name string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%s is a symlink", name)
	}
	if st.Mode&0o044 != 0 {
		return fmt.Errorf("%s is group or other readable", name)
	}
	return nil
}

// reuseSelfSigned reports whether cert and key are regular files that can be kept.
// Symlinks are not followed. A certificate with fewer than 30 days left, or one
// that cannot be parsed, is not reused.
func reuseSelfSigned(cert, key string, now time.Time) (bool, error) {
	if !regularFile(cert) || !regularFile(key) {
		return false, nil
	}
	if !selfSignedFresh(cert, now) {
		return false, nil
	}
	if err := tightenTLSFiles(cert, key); err != nil {
		return false, err
	}
	return true, nil
}

func regularFile(path string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG
}

func selfSignedFresh(path string, now time.Time) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return !cert.NotAfter.Before(now.Add(30 * 24 * time.Hour))
}

func tightenTLSFiles(cert, key string) error {
	if err := os.Chmod(cert, 0o600); err != nil {
		return err
	}
	return os.Chmod(key, 0o600)
}

// GenerateSelfSigned writes an ECDSA P-256 cert for localhost, 127.0.0.1, and ::1.
// bind is included when it is one specific IP. The cert and key are mode 0600
// and owned by the current user.
func GenerateSelfSigned(certPath, keyPath string, now time.Time, bind string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "local-grok-bots", Organization: []string{"local-grok-bots (self-signed)"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  selfSignedIPs(bind),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := writeTLSFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})); err != nil {
		return err
	}
	return writeTLSFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// selfSignedIPs is 127.0.0.1, ::1, and bind when bind is one non-wildcard IP.
func selfSignedIPs(bind string) []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}
	host := strings.TrimSpace(bind)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ips
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() {
		return ips
	}
	for _, have := range ips {
		if have.Equal(ip) {
			return ips
		}
	}
	return append(ips, ip)
}

// writeTLSFile replaces path with body. The bytes land in a new file in the
// same directory, then that file is renamed over path.
func writeTLSFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tls-"+hex.EncodeToString(rnd[:]))
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if err := writeFull(fd, body); err != nil {
		unix.Close(fd)
		unix.Unlink(tmp)
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		unix.Unlink(tmp)
		return err
	}
	if err := unix.Close(fd); err != nil {
		unix.Unlink(tmp)
		return err
	}
	if err := unix.Rename(tmp, path); err != nil {
		unix.Unlink(tmp)
		return err
	}
	return nil
}
