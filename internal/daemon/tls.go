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
	"os"
	"path/filepath"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/config"
)

// tlsConfigured reports whether the daemon will serve HTTPS.
func tlsConfigured(c config.Config) bool {
	return c.TLSSelfSigned || c.TLSCert != "" || c.TLSKey != ""
}

// permBaseFor is the origin the Claude CLI's MCP permission tool calls back.
// The callback is plain HTTP, so under TLS there is no usable base: the CLI
// then runs with prompts off and the broker denies residual asks (fail closed).
func permBaseFor(c config.Config) string {
	if tlsConfigured(c) {
		return ""
	}
	return httpBase(c.BindAddr)
}

// tlsFiles returns the cert/key pair to serve HTTPS with, or "" for plain HTTP.
// Fails closed: a half-configured pair is an error, not a silent HTTP fallback.
func (a *App) tlsFiles() (string, string, error) {
	c := a.cfg
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return "", "", errors.New("TLS_CERT and TLS_KEY must be set together")
	}
	if c.TLSCert != "" {
		_ = a.st.AddLog("", "tls_enabled", map[string]any{"mode": "files", "cert": c.TLSCert})
		return c.TLSCert, c.TLSKey, nil
	}
	if !c.TLSSelfSigned {
		return "", "", nil
	}
	dir := filepath.Join(c.DataDir, "tls")
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := os.Stat(cert); err == nil {
		if _, err := os.Stat(key); err == nil {
			_ = a.st.AddLog("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": false})
			return cert, key, nil
		}
	}
	if err := GenerateSelfSigned(cert, key, time.Now()); err != nil {
		return "", "", err
	}
	_ = a.st.AddLog("", "tls_enabled", map[string]any{"mode": "self_signed", "cert": cert, "generated": true})
	return cert, key, nil
}

// GenerateSelfSigned writes an ECDSA P-256 cert valid for localhost, the
// host name, and every local interface IP. Key file is 0600.
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
	if h, err := os.Hostname(); err == nil && h != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, h, h+".local")
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
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
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
