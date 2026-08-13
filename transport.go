package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
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

func newBrowserTransport(up *url.URL) http.RoundTripper {
	bt := &browserTransport{}
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
	}
	dial := baseDial
	if up != nil {
		upstreamDial, err := upstreamDialer(up, baseDial)
		if err != nil {
			log.Printf("warning: upstream proxy %s unavailable (%v); falling back to direct connections", up.Redacted(), err)
		} else {
			dial = upstreamDial
		}
	}
	bt.h2 = &http2.Transport{
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return dialUTLS(ctx, network, addr, utls.HelloChrome_131, dial)
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
			return dialUTLSH1(ctx, network, addr, dial)
		},
	}
	bt.pt = &http.Transport{
		DisableCompression:    true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		DialContext:           dial,
	}
	return &retryTransport{base: bt}
}

// dialContextFn establishes a raw TCP connection to network/addr.
type dialContextFn func(ctx context.Context, network, addr string) (net.Conn, error)

// upstreamDialer returns a dial function that routes connections through the
// given proxy. Supported schemes:
//
//   - socks5:// and socks5h:// ? SOCKS5. The target hostname is sent to the
//     proxy, so DNS is resolved by the proxy (remote DNS), which also avoids
//     the local resolver leaking lookups.
//   - http:// and https:// ? HTTP CONNECT, optionally with Basic auth in the
//     URL userinfo (http://user:pass@host:port).
//
// Returns nil when up is nil.
func upstreamDialer(up *url.URL, fallback dialContextFn) (dialContextFn, error) {
	if up == nil {
		return nil, nil
	}
	switch strings.ToLower(up.Scheme) {
	case "socks5", "socks5h":
		pd, err := proxy.SOCKS5("tcp", up.Host, socksAuth(up), dialerAdapter(fallback))
		if err != nil {
			return nil, err
		}
		if ctd, ok := pd.(proxy.ContextDialer); ok {
			return ctd.DialContext, nil
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return pd.Dial(network, addr)
		}, nil
	case "http", "https":
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialHTTPConnect(ctx, up, addr, fallback)
		}, nil
	}
	return nil, fmt.Errorf("unsupported proxy scheme %q", up.Scheme)
}

func socksAuth(up *url.URL) *proxy.Auth {
	if up.User == nil {
		return nil
	}
	auth := &proxy.Auth{User: up.User.Username()}
	if pass, ok := up.User.Password(); ok {
		auth.Password = pass
	}
	return auth
}

// dialerAdapter adapts a context dial function to x/net/proxy's Dialer
// interface while keeping context-aware dialing through the proxy library.
type dialerAdapter dialContextFn

func (f dialerAdapter) Dial(network, addr string) (net.Conn, error) {
	return f(context.Background(), network, addr)
}

func (f dialerAdapter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// dialHTTPConnect dials the target addr through an HTTP(S) proxy using the
// CONNECT method, then returns the tunneled connection (keeping any bytes the
// proxy already pipelined readable).
func dialHTTPConnect(ctx context.Context, up *url.URL, addr string, fallback dialContextFn) (net.Conn, error) {
	conn, err := fallback(ctx, "tcp", up.Host)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(up.Scheme, "https") {
		tconn := tls.Client(conn, &tls.Config{ServerName: up.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tconn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{},
		Host:   addr,
		Header: make(http.Header),
	}
	if up.User != nil {
		user := up.User.Username()
		pass, _ := up.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s failed: %s", addr, resp.Status)
	}
	resp.Body.Close()
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn keeps reading from the bufio.Reader after a CONNECT handshake
// so bytes the proxy sent together with its response are not lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
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

func dialUTLS(ctx context.Context, network, addr string, id utls.ClientHelloID, dial dialContextFn) (net.Conn, error) {
	conn, err := dial(ctx, network, addr)
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
func dialUTLSH1(ctx context.Context, network, addr string, dial dialContextFn) (net.Conn, error) {
	conn, err := dial(ctx, network, addr)
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
