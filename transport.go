package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// browserTransport mimics a real Chrome browser's TLS fingerprint (uTLS
// HelloChrome_131) so Cloudflare-style bot checks don't challenge proxied
// traffic. It speaks HTTP/2 when the upstream supports it, falls back to
// HTTP/1.1 otherwise, and retries idempotent requests whose connection was
// reset by the upstream (common on cold connections behind bot protection).
type browserTransport struct {
	h2 http.RoundTripper // HTTP/2 + uTLS Chrome fingerprint
	h1 http.RoundTripper // HTTP/1.1 + uTLS Chrome fingerprint
	pt http.RoundTripper // plain HTTP (no TLS) for http:// targets
}

func newBrowserTransport() http.RoundTripper {
	bt := &browserTransport{}
	bt.h2 = &http2.Transport{
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return dialUTLS(ctx, network, addr, utls.HelloChrome_131)
		},
	}
	bt.h1 = &http.Transport{
		DisableCompression:    true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ForceAttemptHTTP2:     false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUTLSH1(ctx, network, addr)
		},
	}
	bt.pt = &http.Transport{
		DisableCompression:    true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	return &retryTransport{base: bt}
}

func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		return t.pt.RoundTrip(req)
	}
	if isUpgradeRequest(req) {
		// Protocol upgrades (WebSocket) cannot run over HTTP/2; go through
		// the HTTP/1.1 transport so the hijacked connection can be tunneled.
		return t.h1.RoundTrip(req)
	}
	resp, err := t.h2.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// Upstream didn't negotiate HTTP/2 (e.g. an older server). Retry over
	// HTTP/1.1 with the same Chrome fingerprint.
	if isRetryable(err) && (req.Body == nil || req.GetBody != nil) {
		r := req.Clone(req.Context())
		if req.GetBody != nil {
			body, gerr := req.GetBody()
			if gerr == nil {
				r.Body = body
			}
		}
		return t.h1.RoundTrip(r)
	}
	return resp, err
}

// retryTransport retries idempotent requests once when the upstream resets or
// closes the connection before sending a response (EOF on cold connections).
type retryTransport struct {
	base http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil || !isRetryable(err) {
		return resp, err
	}
	if req.Body != nil && req.GetBody == nil {
		return resp, err
	}
	r := req.Clone(req.Context())
	if req.GetBody != nil {
		body, gerr := req.GetBody()
		if gerr != nil {
			return resp, err
		}
		r.Body = body
	}
	return t.base.RoundTrip(r)
}

// isUpgradeRequest reports whether the request asks to switch protocols
// (e.g. Connection: Upgrade + Upgrade: websocket).
func isUpgradeRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	conn, upgrade := "", ""
	for k, v := range req.Header {
		if len(v) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(k, "Connection"):
			conn = v[0]
		case strings.EqualFold(k, "Upgrade"):
			upgrade = v[0]
		}
	}
	if upgrade == "" {
		return false
	}
	for _, tok := range strings.Split(conn, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	for _, s := range []string{
		"connection reset",
		"connection closed",
		"broken pipe",
		"http2: server sent GOAWAY",
		"http2: client connection lost",
		"server does not support HTTP/2",
		"protocol version not supported",
		"EOF",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return false
}

func dialUTLS(ctx context.Context, network, addr string, id utls.ClientHelloID) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{ServerName: host}, id)
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}

// dialUTLSH1 dials with the Chrome fingerprint but only offers HTTP/1.1 in
// ALPN, for upstreams that don't support HTTP/2.
func dialUTLSH1(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	spec, err := chromeH1Spec()
	if err != nil {
		conn.Close()
		return nil, err
	}
	uconn := utls.UClient(conn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, err
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}

// chromeH1Spec returns Chrome's ClientHello fingerprint modified to offer only
// HTTP/1.1. Two details matter:
//
//   - The preset must be applied through HelloCustom. With HelloChrome_131 the
//     preset is re-applied during the handshake, silently discarding any
//     modifications (the wire ClientHello then advertises h2 again).
//   - Chrome's ALPS extension advertises "h2", which makes some CDNs (e.g.
//     Cloudflare) pick HTTP/2 even when ALPN only offers http/1.1. The ALPS
//     extension is kept for fingerprint fidelity, but advertises http/1.1 so
//     the server negotiates HTTP/1.1.
func chromeH1Spec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_131)
	if err != nil {
		return spec, err
	}
	exts := spec.Extensions[:0]
	for _, e := range spec.Extensions {
		switch e.(type) {
		case *utls.ALPNExtension:
			exts = append(exts, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		case *utls.ApplicationSettingsExtension:
			exts = append(exts, &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"http/1.1"}})
		case *utls.ApplicationSettingsExtensionNew:
			exts = append(exts, &utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"http/1.1"}})
		default:
			exts = append(exts, e)
		}
	}
	spec.Extensions = exts
	return spec, nil
}
