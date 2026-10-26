package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
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
		a.log("", "tls_enabled", map[string]any{"mode": "files", "cert": c.TLSCert})
		return c.TLSCert, c.TLSKey, nil
	}
	if !c.TLSSelfSigned {
		return "", "", nil
	}
	dir := filepath.Join(c.DataDir, "tls")
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			if err := tightenTLSFiles(cert, key); err != nil {
				return "", "", err
			}
			a.log("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": false})
			return cert, key, nil
		}
	}
	if err := GenerateSelfSigned(cert, key, time.Now()); err != nil {
		return "", "", err
	}
	a.log("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": true})
	return cert, key, nil
}

func tightenTLSFiles(cert, key string) error {
	if err := os.Chmod(cert, 0o600); err != nil {
		return err
	}
	return os.Chmod(key, 0o600)
}

// GenerateSelfSigned writes an ECDSA P-256 cert for localhost and loopback.
// The cert and key are mode 0600 and owned by the current user.
func GenerateSelfSigned(certPath, keyPath string, now time.Time) error {
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
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if ok && ipn.IP != nil && !ipn.IP.IsLoopback() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
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

func writeTLSFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
