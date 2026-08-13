package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newTestStack starts a mock upstream target and the proxy in front of it.
// The proxy's own origin is the httptest proxy URL; the target is the mock
// upstream, so the path prefix is "<target host>:<port>". The proxy transport
// dials the mock for every upstream connection so subdomains of the target
// (e.g. api.127.0.0.1:<port>) can be exercised end to end.
func TestServeReversePreservesRawPath(t *testing.T) {
	var gotEscaped string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse(up.URL)
	px := NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080"})

	req := httptest.NewRequest("GET", "http://localhost:8080/chatgpt.com/cdn/assets/(_lang).images-cn0rkvyp.js", nil)
	req.URL.RawPath = "/chatgpt.com/cdn/assets/(_lang).images-cn0rkvyp.js"
	rec := httptest.NewRecorder()
	target := &url.URL{Scheme: tgt.Scheme, Host: tgt.Host, Path: "/cdn/assets/(_lang).images-cn0rkvyp.js"}
	px.serveReverse(rec, req, target, "", "/chatgpt.com/")

	if gotEscaped != "/cdn/assets/(_lang).images-cn0rkvyp.js" {
		t.Fatalf("upstream received %q, want raw parentheses preserved", gotEscaped)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestServeReverseRawPathPrefixMismatch verifies the RawPath preservation does
// not misfire when the handler target path is not the prefix suffix (e.g. the
// sentinel route builds target.Path from the full request path while the
// prefix is only used for context). The candidate must be validated against
// the upstream path before it is applied.
func TestServeReverseRawPathPrefixMismatch(t *testing.T) {
	var gotEscaped string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse(up.URL)
	px := NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080"})

	req := httptest.NewRequest("GET", "http://localhost:8080/backend-api/sentinel/req", nil)
	req.URL.RawPath = "/backend-api/sentinel/req"
	rec := httptest.NewRecorder()
	target := &url.URL{Scheme: tgt.Scheme, Host: tgt.Host, Path: "/backend-api/sentinel/req"}
	px.serveReverse(rec, req, target, "", "/backend-api/sentinel/")

	if gotEscaped != "/backend-api/sentinel/req" {
		t.Fatalf("upstream received %q, want full sentinel path kept intact", gotEscaped)
	}
}

// TestServeReversePreservesEncodedPath verifies an already-percent-encoded
// request path keeps its exact encoding when forwarded (no double-encoding).
func TestServeReversePreservesEncodedPath(t *testing.T) {
	var gotEscaped string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEscaped = r.URL.EscapedPath()
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse(up.URL)
	px := NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080"})

	raw := "/chatgpt.com/cdn/assets/%2Ffoo%20bar.js"
	req := httptest.NewRequest("GET", "http://localhost:8080"+raw, nil)
	req.URL.RawPath = raw
	rec := httptest.NewRecorder()
	target := &url.URL{Scheme: tgt.Scheme, Host: tgt.Host, Path: "/cdn/assets//foo bar.js"}
	px.serveReverse(rec, req, target, "", "/chatgpt.com/")

	if gotEscaped != "/cdn/assets/%2Ffoo%20bar.js" {
		t.Fatalf("upstream received %q, want encoded path preserved", gotEscaped)
	}
}

func TestUnrewriteRefererStrippedSPA(t *testing.T) {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	p := NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080", ExtraDomains: []string{"openai.com"}})

	mk := func(rawURL string) *http.Request {
		u, _ := url.Parse(rawURL)
		return &http.Request{URL: u, Header: http.Header{}}
	}
	cases := []struct {
		name string
		req  *http.Request
		ref  string
		want string
	}{
		{"prefixed", mk("https://auth.openai.com/log-in/password"), "http://localhost:8080/auth.openai.com/log-in/password", "https://auth.openai.com/log-in/password"},
		{"stripped-to-auth", mk("https://auth.openai.com/log-in/password"), "http://localhost:8080/log-in/password", "https://auth.openai.com/log-in/password"},
		{"stripped-to-target", mk("https://chatgpt.com/backend-api/x"), "http://localhost:8080/", "https://chatgpt.com/"},
		{"external", mk("https://auth.openai.com/log-in/password"), "https://accounts.google.com/", "https://accounts.google.com/"},
	}
	for _, c := range cases {
		if got := p.unrewriteReferer(c.req, c.ref); got != c.want {
			t.Errorf("%s: unrewriteReferer(%q) = %q, want %q", c.name, c.ref, got, c.want)
		}
	}
}

func TestRealOriginStrippedSPA(t *testing.T) {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	p := NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080", ExtraDomains: []string{"openai.com"}})
	req, _ := http.NewRequest("POST", "https://auth.openai.com/log-in/password", nil)
	req.Header.Set("Referer", "http://localhost:8080/log-in/password")
	req.URL.Host = "auth.openai.com"
	if got := p.realOrigin(req); got != "https://auth.openai.com" {
		t.Errorf("realOrigin = %q, want https://auth.openai.com", got)
	}
	req2, _ := http.NewRequest("POST", "https://chatgpt.com/backend-api/x", nil)
	req2.Header.Set("Referer", "http://localhost:8080/")
	req2.URL.Host = "chatgpt.com"
	if got := p.realOrigin(req2); got != "https://chatgpt.com" {
		t.Errorf("realOrigin = %q, want https://chatgpt.com", got)
	}
}
func newTestStack(t *testing.T) (own *httptest.Server, prefix string) {
	t.Helper()
	targetHost := "127.0.0.1" // replaced below once listener exists

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Host", r.Host)
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Link", `<https://assets-proxy.example.com>`+"; rel=preconnect; crossorigin")
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>x</title></head><body>
<script src="/app.js"></script>
<link rel="stylesheet" href="http://%s/style.css">
<img src="http://api.%s/v1/test.js">
<a href="//%s/v1/y">y</a>
<a href="rel.html">rel</a>
<a href="https://example.com/z">z</a>
</body></html>`, targetHost, targetHost, targetHost)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch("http://%s/api?x=1"); fetch('http://api.%s/v1/t'); var p="/api";`, targetHost, targetHost)
		case "/style.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprintf(w, `@font-face{src:url(/fonts/x.woff)} body{background:url(http://api.%s/img.png)}`, targetHost)
		case "/redir":
			http.Redirect(w, r, "/new", http.StatusFound)
		case "/new":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>new page</body></html>`)
		case "/v1/test.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `fetch("http://api.%s/next"); var q="/v2";`, targetHost)
		case "/cdn-cgi/challenge-platform/test.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `window.__cf="1";`)
		case "/edge-api/bootstrap":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"bootstrap-ok":true}`)
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"url":"http://%s/x","sub":"http://api.%s/a","ext":"https://external.com/b"}`, targetHost, targetHost)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(target.Close)

	prefix = target.Listener.Addr().String()
	targetHost = prefix

	var proxy *Proxy
	own = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(own.Close)

	ownURL, _ := url.Parse(own.URL)
	tgtURL, _ := url.Parse(target.URL)
	proxy = NewProxy(Config{OwnDomain: ownURL, Target: tgtURL, BarePrefixes: []string{"/cdn-cgi/"}, RootFallback: true})
	proxyPlainTransport(proxy).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, prefix)
	}
	return own, prefix
}

// proxyPlainTransport unwraps the upstream transport so tests can point all
// connections at the mock upstream.
func proxyPlainTransport(proxy *Proxy) *http.Transport {
	var bt *browserTransport
	switch tr := proxy.transport.(type) {
	case *retryTransport:
		bt, _ = tr.base.(*browserTransport)
	case *browserTransport:
		bt = tr
	}
	if bt == nil {
		return nil
	}
	pt, _ := bt.pt.(*http.Transport)
	return pt
}

func get(t *testing.T, rawURL string) (int, http.Header, string) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

func TestProxyRootRedirect(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/")
	if status != http.StatusFound {
		t.Fatalf("GET / status = %d, want 302", status)
	}
	want := "/" + prefix + "/"
	if loc := h.Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestProxyExactPrefixRedirect(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/"+prefix)
	if status != http.StatusFound {
		t.Fatalf("GET exact prefix status = %d, want 302", status)
	}
	if loc := h.Get("Location"); loc != "/"+prefix+"/" {
		t.Fatalf("Location = %q, want %q", loc, "/"+prefix+"/")
	}
}

func TestProxyHTMLRewrite(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, body := get(t, own.URL+"/"+prefix+"/")
	if got := h.Get("Link"); !strings.Contains(got, own.URL+"/assets-proxy.example.com") {
		t.Errorf("Link header not rewritten: %q", got)
	}
	if status != http.StatusOK {
		t.Fatalf("GET homepage status = %d, want 200", status)
	}
	checks := []string{
		`<base href="` + own.URL + `/` + prefix + `/">`,
		`<script src="/` + prefix + `/app.js">`,
		`<link rel="stylesheet" href="` + own.URL + `/` + prefix + `/style.css">`,
		`<img src="` + own.URL + `/api.` + prefix + `/v1/test.js">`,
		`href="` + own.URL + `/` + prefix + `/v1/y"`,
		`href="rel.html"`,
		`href="` + own.URL + `/example.com/z"`,
	}
	for _, c := range checks {
		if !strings.Contains(body, c) {
			t.Errorf("homepage missing %q\nbody:\n%s", c, body)
		}
	}
}

func TestProxySubdomainEndToEnd(t *testing.T) {
	own, prefix := newTestStack(t)
	subURL := own.URL + "/api." + prefix + "/v1/test.js"
	status, h, body := get(t, subURL)
	if status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200 (body: %s)", subURL, status, body)
	}
	if got := h.Get("X-Upstream-Host"); got != "api."+prefix {
		t.Fatalf("upstream Host = %q, want %q", got, "api."+prefix)
	}
	if !strings.Contains(body, `fetch("`+own.URL+`/api.`+prefix+`/next")`) {
		t.Errorf("subdomain JS not rewritten:\n%s", body)
	}
	if !strings.Contains(body, `var q="/v2"`) {
		t.Errorf("root-relative JS should stay unchanged:\n%s", body)
	}
}

func TestProxyJSAndCSSRewrite(t *testing.T) {
	own, prefix := newTestStack(t)

	status, _, body := get(t, own.URL+"/"+prefix+"/app.js")
	if status != http.StatusOK {
		t.Fatalf("GET app.js status = %d, want 200", status)
	}
	for _, c := range []string{
		`fetch("` + own.URL + `/` + prefix + `/api?x=1")`,
		`fetch('` + own.URL + `/api.` + prefix + `/v1/t')`,
		`var p="/api"`,
	} {
		if !strings.Contains(body, c) {
			t.Errorf("app.js missing %q\nbody:\n%s", c, body)
		}
	}

	status, _, body = get(t, own.URL+"/"+prefix+"/style.css")
	if status != http.StatusOK {
		t.Fatalf("GET style.css status = %d, want 200", status)
	}
	for _, c := range []string{
		`url(` + own.URL + `/` + prefix + `/fonts/x.woff)`,
		`url(` + own.URL + `/api.` + prefix + `/img.png)`,
	} {
		if !strings.Contains(body, c) {
			t.Errorf("style.css missing %q\nbody:\n%s", c, body)
		}
	}
}

func TestProxyJSONRewrite(t *testing.T) {
	own, prefix := newTestStack(t)
	status, _, body := get(t, own.URL+"/"+prefix+"/api")
	if status != http.StatusOK {
		t.Fatalf("GET api status = %d, want 200", status)
	}
	checks := []string{
		`"url":"` + own.URL + `/` + prefix + `/x"`,
		`"sub":"` + own.URL + `/api.` + prefix + `/a"`,
		`"ext":"` + own.URL + `/external.com/b"`,
	}
	for _, c := range checks {
		if !strings.Contains(body, c) {
			t.Errorf("api JSON missing %q\nbody:\n%s", c, body)
		}
	}
}

func TestProxyRedirectRewrite(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/"+prefix+"/redir")
	if status != http.StatusFound {
		t.Fatalf("GET /redir status = %d, want 302", status)
	}
	want := own.URL + "/" + prefix + "/new"
	if loc := h.Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestProxyRootFallback(t *testing.T) {
	own, _ := newTestStack(t)
	status, h, body := get(t, own.URL+"/edge-api/bootstrap?x=1")
	if status != http.StatusOK {
		t.Fatalf("GET unprefixed path status = %d, want 200 (fallback to target)", status)
	}
	if got := h.Get("X-Upstream-Path"); got != "/edge-api/bootstrap" {
		t.Fatalf("upstream path = %q, want /edge-api/bootstrap", got)
	}
	if !strings.Contains(body, "bootstrap-ok") {
		t.Errorf("fallback body unexpected:\n%s", body)
	}
}

func TestProxyRootFallbackDisabled404(t *testing.T) {
	tgt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream", http.StatusTeapot)
	}))
	defer tgt.Close()
	tgtURL, _ := url.Parse(tgt.URL)

	var proxy *Proxy
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxy.ServeHTTP(w, r) }))
	defer srv.Close()
	ownURL, _ := url.Parse(srv.URL)
	proxy = NewProxy(Config{OwnDomain: ownURL, Target: tgtURL, RootFallback: false})
	status, _, _ := get(t, srv.URL+"/example.com/x")
	if status != http.StatusNotFound {
		t.Fatalf("GET unknown host status = %d, want 404", status)
	}
}

func TestProxyEmbeddedAbsoluteURLPath(t *testing.T) {
	own, prefix := newTestStack(t)
	// App re-prefixed an already-proxied URL with the origin:
	// /https://own/<host-prefix>//v1/test.js
	ownHost := strings.TrimPrefix(own.URL, "http://")
	status, h, body := get(t, own.URL+"/https://"+ownHost+"/"+prefix+"//v1/test.js")
	if status != http.StatusOK {
		t.Fatalf("GET embedded-own status = %d, want 200 (body: %.100s)", status, body)
	}
	if got := h.Get("X-Upstream-Path"); got != "/v1/test.js" {
		t.Fatalf("upstream path = %q, want /v1/test.js", got)
	}
	// Embedded external host form: /https://example.com/v1/test.js
	status, h, _ = get(t, own.URL+"/https://example.com/v1/test.js")
	if status != http.StatusOK {
		t.Fatalf("GET embedded-external status = %d, want 200", status)
	}
	if got := h.Get("X-Upstream-Host"); got != "example.com" {
		t.Fatalf("upstream host = %q, want example.com", got)
	}
	if got := h.Get("X-Upstream-Path"); got != "/v1/test.js" {
		t.Fatalf("upstream path = %q, want /v1/test.js", got)
	}
}

func TestProxyHostPrefixDoubleSlash(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/"+prefix+"//v1/test.js")
	if status != http.StatusOK {
		t.Fatalf("GET double-slash status = %d, want 200", status)
	}
	if got := h.Get("X-Upstream-Path"); got != "/v1/test.js" {
		t.Fatalf("upstream path = %q, want /v1/test.js", got)
	}
}

func TestProxyStripForCatchAllHostPage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Host", r.Host)
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>auth</title></head><body><form action="/log-in/password" method="post"><input name="x"></form></body></html>`)
	}))
	defer target.Close()
	prefix := target.Listener.Addr().String()

	var proxy *Proxy
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))
	defer own.Close()
	ownURL, _ := url.Parse(own.URL)
	tgtURL, _ := url.Parse(target.URL)
	proxy = NewProxy(Config{OwnDomain: ownURL, Target: tgtURL, RootFallback: true})
	proxyPlainTransport(proxy).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, prefix)
	}

	// auth.openai.com is not a configured extra domain; it is proxied via the
	// catch-all. Its pages must keep the host prefix in the URL (no SPA strip
	// script), so the page URL stays consistent with the injected <base> href.
	status, h, body := get(t, own.URL+"/auth.openai.com/log-in/password")
	if status != http.StatusOK {
		t.Fatalf("GET auth page status = %d", status)
	}
	if got := h.Get("X-Upstream-Host"); got != "auth.openai.com" {
		t.Fatalf("upstream host = %q, want auth.openai.com", got)
	}
	if strings.Contains(body, "history.replaceState") {
		t.Errorf("page must not strip the host prefix from the URL:\n%s", body)
	}
	if !strings.Contains(body, `<base href="`+own.URL+`/auth.openai.com/log-in/password">`) {
		t.Errorf("base href missing host prefix:\n%s", body)
	}
	if !strings.Contains(body, `action="/auth.openai.com/log-in/password"`) {
		t.Errorf("form action not rewritten to host prefix:\n%s", body)
	}
}
func TestProxyExtraDomainEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Host", r.Host)
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><head></head><body><a href="https://auth.openai.com/log-in/password">login</a></body></html>`)
	}))
	defer target.Close()
	prefix := target.Listener.Addr().String()

	var proxy *Proxy
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	}))
	defer own.Close()
	ownURL, _ := url.Parse(own.URL)
	tgtURL, _ := url.Parse(target.URL)
	proxy = NewProxy(Config{OwnDomain: ownURL, Target: tgtURL, ExtraDomains: []string{"openai.com"}, RootFallback: true})
	proxyPlainTransport(proxy).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, prefix)
	}

	// HTML containing auth.openai.com must be rewritten to the proxied form
	status, _, body := get(t, own.URL+"/"+prefix+"/")
	if status != http.StatusOK {
		t.Fatalf("GET homepage status = %d", status)
	}
	if !strings.Contains(body, `href="`+own.URL+`/auth.openai.com/log-in/password"`) {
		t.Errorf("auth.openai.com link not rewritten:\n%s", body)
	}
	// and the auth.openai.com path must route upstream to auth.openai.com
	status, h, _ := get(t, own.URL+"/auth.openai.com/log-in/password")
	if status != http.StatusOK {
		t.Fatalf("GET auth path status = %d", status)
	}
	if got := h.Get("X-Upstream-Host"); got != "auth.openai.com" {
		t.Fatalf("upstream Host = %q, want auth.openai.com", got)
	}
}

func TestProxyBarePrefix(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, body := get(t, own.URL+"/cdn-cgi/challenge-platform/test.js")
	if status != http.StatusOK {
		t.Fatalf("GET bare prefix status = %d, want 200", status)
	}
	if got := h.Get("X-Upstream-Host"); got != prefix {
		t.Fatalf("upstream Host = %q, want %q", got, prefix)
	}
	if !strings.Contains(body, `window.__cf="1";`) {
		t.Errorf("bare prefix body unexpected:\n%s", body)
	}
}

func TestProxyRootRedirectKeepsQuery(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/?__cf_chl_rt_tk=abc123")
	if status != http.StatusFound {
		t.Fatalf("GET / status = %d, want 302", status)
	}
	want := "/" + prefix + "/?__cf_chl_rt_tk=abc123"
	if loc := h.Get("Location"); loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}
}

func TestProxyUpstreamPathPreserved(t *testing.T) {
	own, prefix := newTestStack(t)
	status, h, _ := get(t, own.URL+"/"+prefix+"/")
	if status != http.StatusOK {
		t.Fatalf("GET homepage status = %d, want 200", status)
	}
	if got := h.Get("X-Upstream-Path"); got != "/" {
		t.Fatalf("upstream saw path %q, want /", got)
	}
	if got := h.Get("X-Upstream-Host"); got != prefix {
		t.Fatalf("upstream Host = %q, want %q", got, prefix)
	}
}

// TestSentinelServedThroughProxy verifies the Sentinel anti-bot frame is
// synthesized on the own origin with its SDK URL rewritten through the proxy
// (when the sentinel host is proxied), and that host-prefixed
// sentinel.openai.com paths route to the sentinel upstream even when the host
// is listed as a direct domain. That keeps the SDK's /backend-api/sentinel/req
// calls on the own domain.
func TestSentinelServedThroughProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Host", r.Host)
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(`var SentinelSDK=1;`))
	}))
	defer target.Close()

	start := func(direct []string) (*httptest.Server, *Proxy) {
		var proxy *Proxy
		own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxy.ServeHTTP(w, r) }))
		ownURL, _ := url.Parse(own.URL)
		tgtURL, _ := url.Parse(target.URL)
		proxy = NewProxy(Config{OwnDomain: ownURL, Target: tgtURL, ExtraDomains: []string{"openai.com"}, DirectDomains: direct, RootFallback: true})
		proxyPlainTransport(proxy).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target.Listener.Addr().String())
		}
		return own, proxy
	}

	// Proxied sentinel host: the frame is synthesized with the SDK rewritten
	// through the proxy.
	own, _ := start(nil)
	defer own.Close()
	status, _, body := get(t, own.URL+"/backend-api/sentinel/frame.html?sv=test123")
	if status != http.StatusOK {
		t.Fatalf("GET sentinel frame status = %d, want 200", status)
	}
	wantSrc := own.URL + "/" + sentinelHost + "/sentinel/test123/sdk.js"
	if !strings.Contains(body, wantSrc) {
		t.Fatalf("synthesized frame does not load the SDK through the proxy:\n%s", body)
	}

	// Host-prefixed sentinel paths route to the sentinel upstream even when
	// sentinel.openai.com is listed as a direct domain.
	own2, _ := start([]string{"sentinel.openai.com"})
	defer own2.Close()
	status, h, _ := get(t, own2.URL+"/sentinel.openai.com/sentinel/test123/sdk.js")
	if status != http.StatusOK {
		t.Fatalf("GET sentinel SDK status = %d, want 200", status)
	}
	if got := h.Get("X-Upstream-Host"); got != sentinelHost {
		t.Fatalf("upstream Host = %q, want %q", got, sentinelHost)
	}
}

// TestProxyCatchAllRouting verifies that the first path segment of an incoming
// request routes upstream to that host when it looks like a hostname (catch-all),
// while ordinary site paths (robots.txt) keep falling back to the target host.
func TestProxyLocalhostHostPort404(t *testing.T) {
	own, _ := newTestStack(t)
	// A host:port first segment with an unroutable hostname must 404 locally
	// instead of falling back to the target.
	for _, p := range []string{"/localhost:3000/api/auth/error", "/intranet:8080/x"} {
		status, _, _ := get(t, own.URL+p)
		if status != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", p, status)
		}
	}
	// Ordinary SPA paths still fall back to the target.
	status, h, _ := get(t, own.URL+"/app.js")
	if status != http.StatusOK || h.Get("X-Upstream-Host") == "" {
		t.Errorf("SPA fallback broken: status=%d host=%q", status, h.Get("X-Upstream-Host"))
	}
}

func TestProxyCatchAllRouting(t *testing.T) {
	own, prefix := newTestStack(t)

	status, h, _ := get(t, own.URL+"/example.com/robots.txt")
	if got := h.Get("X-Upstream-Host"); got != "example.com" {
		t.Fatalf("catch-all upstream Host = %q, want example.com (status %d)", got, status)
	}

	status, h, _ = get(t, own.URL+"/robots.txt")
	if got := h.Get("X-Upstream-Host"); got != prefix {
		t.Fatalf("root fallback upstream Host = %q, want %q (status %d)", got, prefix, status)
	}
}
