package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	defaultCertFile = "webproxy-cert.pem"
	defaultKeyFile  = "webproxy-key.pem"
)

// resolveTLSFiles returns the certificate and key file paths to serve.
// Custom paths are used as-is; otherwise a self-signed certificate is
// generated once, saved next to the binary and reused on later starts.
func resolveTLSFiles(certFile, keyFile, hostname string) (string, string, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return "", "", fmt.Errorf("both -cert and -key must be provided")
		}
		return certFile, keyFile, nil
	}
	if fileExists(defaultCertFile) && fileExists(defaultKeyFile) {
		return defaultCertFile, defaultKeyFile, nil
	}
	certPEM, keyPEM, err := generateSelfSigned(hostname)
	if err != nil {
		return "", "", fmt.Errorf("generate self-signed certificate: %w", err)
	}
	if err := os.WriteFile(defaultCertFile, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(defaultKeyFile, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return defaultCertFile, defaultKeyFile, nil
}

// generateSelfSigned creates an ECDSA P-256 self-signed certificate valid for
// one year, covering the given hostname, localhost and loopback addresses.
func generateSelfSigned(hostname string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"webproxy self-signed"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, hostname, "localhost")
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
