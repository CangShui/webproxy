package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateSelfSigned(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSigned("example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no CERTIFICATE block in cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range cert.DNSNames {
		if d == "example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("DNSNames = %v, want example.com", cert.DNSNames)
	}
	if !hasIP(cert.IPAddresses, "127.0.0.1") {
		t.Errorf("IPAddresses = %v, want 127.0.0.1", cert.IPAddresses)
	}
	if keyPEM == nil || len(keyPEM) == 0 {
		t.Error("empty key PEM")
	}
}

func hasIP(ips []net.IP, want string) bool {
	for _, ip := range ips {
		if ip.String() == want {
			return true
		}
	}
	return false
}

func TestResolveTLSFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	cert1, key1, err := resolveTLSFiles("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if !fileExists(cert1) || !fileExists(key1) {
		t.Fatalf("generated files missing: %s %s", cert1, key1)
	}
	cert2, key2, err := resolveTLSFiles("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if cert2 != cert1 || key2 != key1 {
		t.Errorf("cert files not reused: (%s,%s) vs (%s,%s)", cert1, key1, cert2, key2)
	}
	// custom paths must be returned as-is and validated
	if _, _, err := resolveTLSFiles("a.pem", "", "localhost"); err == nil {
		t.Error("expected error when only -cert is given")
	}
}

func TestSelfSignedServesTLS(t *testing.T) {
	t.Chdir(t.TempDir())
	certFile, keyFile, err := resolveTLSFiles("", "", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "tls-ok")
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client() // httptest client trusts the server cert
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "tls-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}
