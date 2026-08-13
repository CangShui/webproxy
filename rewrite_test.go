package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testProxy(t *testing.T) *Proxy {
	t.Helper()
	own, err := url.Parse("http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := url.Parse("https://claude.ai")
	if err != nil {
		t.Fatal(err)
	}
	return NewProxy(Config{OwnDomain: own, Target: tgt, Listen: ":8080"})
}

func TestRewriteFormURLInputs(t *testing.T) {
	p := testProxy(t)
	body := `<!DOCTYPE html><html><head><title>x</title></head><body>
<form method="post" action="/login">
<input type="hidden" name="redirect_uri" value="https://claude.ai/api/callback">
<input type="hidden" name="state" value="abc123">
<input type="hidden" name="callback_url" value="//api.claude.ai/v1/x">
<input type="text" name="email" value="a@b.com">
<input type="hidden" name="next" value="/relative/path">
<button name="redirect" value="https://claude.ai/btn">go</button>
</form>
</body></html>`
	got := string(p.rewriteHTML([]byte(body), p.ownOrigin+"/claude.ai/", ""))
	checks := []string{
		`name="redirect_uri" value="http://localhost:8080/claude.ai/api/callback"`,
		`name="state" value="abc123"`,
		`name="callback_url" value="http://localhost:8080/api.claude.ai/v1/x"`,
		`name="email" value="a@b.com"`,
		`name="next" value="/relative/path"`,
		`name="redirect" value="http://localhost:8080/claude.ai/btn"`,
	}
	for _, c := range checks {
		if !strings.Contains(got, c) {
			t.Errorf("rewritten HTML missing %q\nbody:\n%s", c, got)
		}
	}
}

func TestUnrewriteURLParams(t *testing.T) {
	p := testProxy(t)
	cases := []struct{ in, want string }{
		{
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Fclaude.ai%2Fapi%2Fauth%2Fcallback",
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fauth%2Fcallback",
		},
		{
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Fapi.claude.ai%2Fv1%2Fx&state=1",
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fapi.claude.ai%2Fv1%2Fx&state=1",
		},
		{
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fexample.com%2Fcb&state=1",
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fexample.com%2Fcb&state=1",
		},
		{
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Fsome-other-path",
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Flocalhost%3A8080%2Fsome-other-path",
		},
		{
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fauth%2Fcallback",
			"http://localhost:8080/claude.ai/oauth?redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fauth%2Fcallback",
		},
		{"http://localhost:8080/claude.ai/oauth?state=1", "http://localhost:8080/claude.ai/oauth?state=1"},
	}
	for _, c := range cases {
		if got := p.unrewriteURLParams(c.in); got != c.want {
			t.Errorf("unrewriteURLParams(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnrewriteURL(t *testing.T) {
	p := testProxy(t)
	cases := []struct{ in, want string }{
		{"http://localhost:8080/claude.ai/style.css", "https://claude.ai/style.css"},
		{"http://localhost:8080/claude.ai/", "https://claude.ai/"},
		{"http://localhost:8080/api.claude.ai/v1/x?q=1#f", "https://api.claude.ai/v1/x?q=1#f"},
		{"http://localhost:8080/unauth-mweb/events/page-view", "https://claude.ai/unauth-mweb/events/page-view"},
		{"http://localhost:8080/", "https://claude.ai/"},
		{"https://example.com/x", "https://example.com/x"},
		{"http://other.host/x", "http://other.host/x"},
		{"rel/path", "rel/path"},
	}
	for _, c := range cases {
		if got := p.unrewriteURL(c.in); got != c.want {
			t.Errorf("unrewriteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteRequestHeaders(t *testing.T) {
	p := testProxy(t)
	req := httptest.NewRequest("POST", "http://localhost:8080/claude.ai/unauth-mweb/events", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set("Referer", "http://localhost:8080/claude.ai/")
	p.rewriteRequestHeaders(req)
	if got := req.Header.Get("Origin"); got != "https://claude.ai" {
		t.Errorf("Origin = %q, want https://claude.ai", got)
	}
	if got := req.Header.Get("Referer"); got != "https://claude.ai/" {
		t.Errorf("Referer = %q, want https://claude.ai/", got)
	}

	// Referer on a proxied subdomain page maps to that host's origin.
	req2 := httptest.NewRequest("POST", "http://localhost:8080/api.claude.ai/v1/x", nil)
	req2.Header.Set("Origin", "http://localhost:8080")
	req2.Header.Set("Referer", "http://localhost:8080/api.claude.ai/")
	p.rewriteRequestHeaders(req2)
	if got := req2.Header.Get("Origin"); got != "https://api.claude.ai" {
		t.Errorf("Origin = %q, want https://api.claude.ai", got)
	}

	// Foreign origin is left alone.
	req3 := httptest.NewRequest("POST", "http://localhost:8080/claude.ai/x", nil)
	req3.Header.Set("Origin", "https://example.com")
	p.rewriteRequestHeaders(req3)
	if got := req3.Header.Get("Origin"); got != "https://example.com" {
		t.Errorf("Origin = %q, want unchanged https://example.com", got)
	}
}

func TestRewriteAccessControlAllowOrigin(t *testing.T) {
	p := testProxy(t)
	// exercise through modifyResponse by building a fake response
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Access-Control-Allow-Origin", "https://claude.ai")
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	resp.Header.Set("Content-Type", "application/json")
	resp.StatusCode = http.StatusOK
	resp.Body = io.NopCloser(strings.NewReader("{}"))
	p.modifyResponse(resp)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:8080" {
		t.Errorf("ACAO = %q, want http://localhost:8080", got)
	}
	// wildcard stays
	resp2 := &http.Response{Header: http.Header{}}
	resp2.Header.Set("Access-Control-Allow-Origin", "*")
	resp2.Header.Set("Content-Type", "application/json")
	resp2.StatusCode = http.StatusOK
	resp2.Body = io.NopCloser(strings.NewReader("{}"))
	p.modifyResponse(resp2)
	if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want *", got)
	}
}

func TestRewriteURL(t *testing.T) {
	p := testProxy(t)
	cases := []struct{ in, want string }{
		{"https://claude.ai/style.css", "http://localhost:8080/claude.ai/style.css"},
		{"https://claude.ai", "http://localhost:8080/claude.ai"},
		{"https://api.claude.ai/v1/test.js", "http://localhost:8080/api.claude.ai/v1/test.js"},
		{"https://api.claude.ai:8443/v1/x?q=1#f", "http://localhost:8080/api.claude.ai:8443/v1/x?q=1#f"},
		{"//api.claude.ai/v1/x", "http://localhost:8080/api.claude.ai/v1/x"},
		{"/style.css", "http://localhost:8080/claude.ai/style.css"},
		{"/path?x=1&y=2", "http://localhost:8080/claude.ai/path?x=1&y=2"},
		{"/claude.ai/style.css", "/claude.ai/style.css"},
		{"/api.claude.ai/v1/x", "/api.claude.ai/v1/x"},
		{"rel.css", "rel.css"},
		{"./rel.css", "./rel.css"},
		{"https://example.com/x", "http://localhost:8080/example.com/x"},
		{"https://claude.ai.evil.com/x", "http://localhost:8080/claude.ai.evil.com/x"},
		{"javascript:void(0)", "javascript:void(0)"},
		{"data:image/png;base64,AAAA", "data:image/png;base64,AAAA"},
		{"mailto:a@b.com", "mailto:a@b.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := p.rewriteURL(c.in); got != c.want {
			t.Errorf("rewriteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLocalhostNeverProxied(t *testing.T) {
	p := testProxy(t)
	for _, host := range []string{"localhost", "localhost:3000", "127.0.0.1", "127.0.0.1:3000", "[::1]", "[::1]:3000", "intranet"} {
		if p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = true, want false", host)
		}
	}
	for _, host := range []string{"claude.ai", "api.claude.ai", "example.com:8443", "api.claude.ai:8443"} {
		if !p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = false, want true", host)
		}
	}
	cases := []struct{ in, want string }{
		{"http://localhost:3000/api/auth/error", "http://localhost:3000/api/auth/error"},
		{"//localhost:3000/api/auth/error", "//localhost:3000/api/auth/error"},
		{"http://127.0.0.1:3000/x", "http://127.0.0.1:3000/x"},
	}
	for _, c := range cases {
		if got := p.rewriteURL(c.in); got != c.want {
			t.Errorf("rewriteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func testProxyExtra(t *testing.T) *Proxy {
	t.Helper()
	p := testProxy(t)
	p.extraDomains = append(p.extraDomains, "openai.com")
	return p
}

func TestRewriteURLPageHost(t *testing.T) {
	p := testProxyExtra(t)
	cases := []struct{ in, pageHost, want string }{
		{"/log-in/password", "auth.openai.com", "http://localhost:8080/auth.openai.com/log-in/password"},
		{"/style.css", "auth.openai.com", "http://localhost:8080/auth.openai.com/style.css"},
		{"/log-in/password?x=1&y=2", "auth.openai.com", "http://localhost:8080/auth.openai.com/log-in/password?x=1&y=2"},
		{"/auth.openai.com/x", "auth.openai.com", "/auth.openai.com/x"},
		{"/openai.com/x", "auth.openai.com", "/openai.com/x"},
		{"/claude.ai/x", "auth.openai.com", "/claude.ai/x"},
		{"/foo", "", "http://localhost:8080/claude.ai/foo"},
		{"https://auth.openai.com/log-in/password", "auth.openai.com", "http://localhost:8080/auth.openai.com/log-in/password"},
		{"//auth.openai.com/x", "auth.openai.com", "http://localhost:8080/auth.openai.com/x"},
		{"rel.css", "auth.openai.com", "rel.css"},
	}
	for _, c := range cases {
		if got := p.rewriteURLIn(c.in, c.pageHost); got != c.want {
			t.Errorf("rewriteURLIn(%q, %q) = %q, want %q", c.in, c.pageHost, got, c.want)
		}
	}
}

func TestRewriteHTMLExtraDomainFormAction(t *testing.T) {
	p := testProxyExtra(t)
	in := `<!DOCTYPE html><html><head><title>x</title></head><body>
<form method="post" action="/log-in/password">
<input type="hidden" name="username" value="a@b.com">
<input type="password" name="current-password">
<button name="intent" value="validate">Continue</button>
</form>
<img src="/assets/logo.png">
<a href="/log-in-or-create-account?usernameKind=email">Edit</a>
</body></html>`
	pageURL := "http://localhost:8080/auth.openai.com/log-in/password"
	out := string(p.rewriteHTML([]byte(in), pageURL, ""))
	checks := []string{
		`<base href="http://localhost:8080/auth.openai.com/log-in/password">`,
		`action="http://localhost:8080/auth.openai.com/log-in/password"`,
		`src="http://localhost:8080/auth.openai.com/assets/logo.png"`,
		`href="http://localhost:8080/auth.openai.com/log-in-or-create-account?usernameKind=email"`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("rewritten HTML missing %q\noutput:\n%s", c, out)
		}
	}
}

func TestRewriteHTMLPreservesReactRouterFormAction(t *testing.T) {
	p := testProxyExtra(t)
	in := `<!DOCTYPE html><html><head><title>x</title></head><body>
<form method="post" data-discover="true" action="/log-in/password">
<input type="password" name="current-password">
</form>
<form method="post" action="/plain">
<input type="text" name="x">
</form>
</body></html>`
	pageURL := "http://localhost:8080/auth.openai.com/log-in/password"
	out := string(p.rewriteHTML([]byte(in), pageURL, ""))
	if !strings.Contains(out, `action="/log-in/password"`) {
		t.Errorf("React Router form action was rewritten; want it left as-is\noutput:\n%s", out)
	}
	if !strings.Contains(out, `action="http://localhost:8080/auth.openai.com/plain"`) {
		t.Errorf("plain form action not rewritten\noutput:\n%s", out)
	}
}
func TestDirectDomainNotProxied(t *testing.T) {
	p := testProxyExtra(t)
	p.directDomains = append(p.directDomains, "sentinel.openai.com")
	if p.isProxyHost("sentinel.openai.com") {
		t.Error("sentinel.openai.com should not be a proxy host")
	}
	if !p.isProxyHost("auth.openai.com") {
		t.Error("auth.openai.com should still be a proxy host")
	}
	if got := p.rewriteURL("https://sentinel.openai.com/backend-api/sentinel/frame.html"); got != "https://sentinel.openai.com/backend-api/sentinel/frame.html" {
		t.Errorf("direct-domain URL was rewritten: %q", got)
	}
	out := string(p.rewriteAbsURLs([]byte(`var u="https://sentinel.openai.com/backend-api/sentinel/sdk.js"; var a="https://auth.openai.com/x";`)))
	if !strings.Contains(out, `var u="https://sentinel.openai.com/backend-api/sentinel/sdk.js"`) {
		t.Errorf("direct-domain JS URL was rewritten: %s", out)
	}
	if !strings.Contains(out, `var a="http://localhost:8080/auth.openai.com/x"`) {
		t.Errorf("proxied JS URL not rewritten: %s", out)
	}
	shim := p.runtimeShimScript()
	if !strings.Contains(shim, `"sentinel.openai.com"`) {
		t.Errorf("shim missing DIRECT host: %.300s", shim)
	}
}

func TestRewriteLocation(t *testing.T) {
	p := testProxyExtra(t)
	cases := []struct{ in, pageURL, want string }{
		{"/new", "http://localhost:8080/auth.openai.com/api/accounts/authorize", "http://localhost:8080/auth.openai.com/new"},
		{"/new", "http://localhost:8080/claude.ai/redir", "http://localhost:8080/claude.ai/new"},
		{"/new", "http://localhost:8080/redir", "/new"},
		{"https://auth.openai.com/log-in/password", "http://localhost:8080/auth.openai.com/x", "http://localhost:8080/auth.openai.com/log-in/password"},
		{"//auth.openai.com/y", "http://localhost:8080/auth.openai.com/x", "http://localhost:8080/auth.openai.com/y"},
		{"rel", "http://localhost:8080/claude.ai/redir", "rel"},
		{"https://example.com/z", "http://localhost:8080/claude.ai/redir", "http://localhost:8080/example.com/z"},
	}
	for _, c := range cases {
		if got := p.rewriteLocation(c.in, c.pageURL); got != c.want {
			t.Errorf("rewriteLocation(%q, %q) = %q, want %q", c.in, c.pageURL, got, c.want)
		}
	}
}

func TestRewriteLinkHeader(t *testing.T) {
	p := testProxy(t)
	cases := []struct{ in, pageURL, want string }{
		{
			`<https://assets-proxy.anthropic.com>; rel=preconnect; crossorigin, <https://assets-proxy.anthropic.com/x/index-Do7Ouh6O.js>; rel=modulepreload; crossorigin`,
			"http://localhost:8080/claude.ai/login",
			`<http://localhost:8080/assets-proxy.anthropic.com>; rel=preconnect; crossorigin, <http://localhost:8080/assets-proxy.anthropic.com/x/index-Do7Ouh6O.js>; rel=modulepreload; crossorigin`,
		},
		{
			`<https://newassets.hcaptcha.com/1.11.0/hcaptcha.js>; rel=preload; as=script`,
			"http://localhost:8080/claude.ai/login",
			`<https://newassets.hcaptcha.com/1.11.0/hcaptcha.js>; rel=preload; as=script`,
		},
	}
	for _, c := range cases {
		if got := p.rewriteLinkHeader(c.in, c.pageURL); got != c.want {
			t.Errorf("rewriteLinkHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRewriteHTML(t *testing.T) {
	p := testProxy(t)
	in := `<!DOCTYPE html><html><head><title>x</title><script src="/app.js"></script>
<link rel="stylesheet" href="https://claude.ai/style.css">
<img src="https://api.claude.ai/v1/test.js">
</head><body>
<a href="//api.claude.ai/v1/y">y</a>
<a href="rel.html">rel</a>
<a href="/docs">docs</a>
<a href="https://example.com/z">z</a>
<script>var u="https://claude.ai/api";</script>
</body></html>`
	pageURL := "http://localhost:8080/claude.ai/"
	out := string(p.rewriteHTML([]byte(in), pageURL, ""))

	checks := []string{
		`<base href="http://localhost:8080/claude.ai/">`,
		`<script src="http://localhost:8080/claude.ai/app.js">`,
		`<link rel="stylesheet" href="http://localhost:8080/claude.ai/style.css">`,
		`<img src="http://localhost:8080/api.claude.ai/v1/test.js">`,
		`href="http://localhost:8080/api.claude.ai/v1/y"`,
		`href="rel.html"`,
		`href="http://localhost:8080/claude.ai/docs"`,
		`href="http://localhost:8080/example.com/z"`,
		`var u="http://localhost:8080/claude.ai/api";`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("rewritten HTML missing %q\noutput:\n%s", c, out)
		}
	}
	// base must be injected right after <head>
	if i := strings.Index(out, "<head>"); i >= 0 {
		after := out[i+len("<head>"):]
		if !strings.HasPrefix(after, `<base href=`) {
			t.Errorf("base not injected right after <head>:\n%s", out)
		}
	} else {
		t.Errorf("no <head> found in output")
	}
}

func TestRewriteHTMLExistingBase(t *testing.T) {
	p := testProxy(t)
	in := `<html><head><base href="https://claude.ai/"><title>x</title></head><body>ok</body></html>`
	out := string(p.rewriteHTML([]byte(in), "http://localhost:8080/claude.ai/", ""))
	if !strings.Contains(out, `<base href="http://localhost:8080/claude.ai/">`) {
		t.Errorf("existing base not rewritten:\n%s", out)
	}
	if strings.Count(out, "<base ") != 1 {
		t.Errorf("expected exactly one <base> tag:\n%s", out)
	}
}

func TestRewriteHTMLInjectsStripScript(t *testing.T) {
	p := testProxy(t)
	in := `<html><head><title>x</title></head><body>hi</body></html>`
	out := string(p.rewriteHTML([]byte(in), "http://localhost:8080/claude.ai/login", "/claude.ai"))
	if !strings.Contains(out, `<base href="http://localhost:8080/claude.ai/login">`) {
		t.Errorf("base missing:\n%s", out)
	}
	if !strings.Contains(out, `var P="/claude.ai"`) {
		t.Errorf("strip script missing prefix:\n%s", out)
	}
	if !strings.Contains(out, "history.replaceState") {
		t.Errorf("strip script missing replaceState:\n%s", out)
	}
	// without stripPrefix no shim is injected
	out2 := string(p.rewriteHTML([]byte(in), "http://localhost:8080/claude.ai/login", ""))
	if strings.Contains(out2, "history.replaceState") {
		t.Errorf("strip script should not be injected when stripPrefix is empty:\n%s", out2)
	}
}

func TestRewriteHTMLDropsIntegrity(t *testing.T) {
	p := testProxy(t)
	in := `<html><head></head><body><script src="/x.js" integrity="sha256-abc" crossorigin="anonymous"></script></body></html>`
	out := string(p.rewriteHTML([]byte(in), "http://localhost:8080/claude.ai/", ""))
	if strings.Contains(out, "integrity") {
		t.Errorf("integrity attribute should be removed:\n%s", out)
	}
	if !strings.Contains(out, `src="http://localhost:8080/claude.ai/x.js"`) {
		t.Errorf("script src not rewritten:\n%s", out)
	}
	if !strings.Contains(out, `crossorigin="anonymous"`) {
		t.Errorf("crossorigin attribute should be kept:\n%s", out)
	}
}

func TestRewriteCSS(t *testing.T) {
	p := testProxy(t)
	in := `@font-face{src:url(/fonts/x.woff)} body{background:url(https://api.claude.ai/img.png)} @import "https://claude.ai/theme.css"; .a{background:url("rel.png")}`
	out := p.rewriteCSS(in)
	checks := []string{
		`url(http://localhost:8080/claude.ai/fonts/x.woff)`,
		`url(http://localhost:8080/api.claude.ai/img.png)`,
		`@import "http://localhost:8080/claude.ai/theme.css"`,
		`url("rel.png")`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("rewritten CSS missing %q\noutput:\n%s", c, out)
		}
	}
}

func TestRewriteAbsURLs(t *testing.T) {
	p := testProxy(t)
	in := `fetch("https://claude.ai/api?x=1"); fetch('//api.claude.ai/v1/t'); var a="https://external.com/z"; var p="/api";`
	out := string(p.rewriteAbsURLs([]byte(in)))
	checks := []string{
		`fetch("http://localhost:8080/claude.ai/api?x=1")`,
		`"http://localhost:8080/external.com/z"`,
		`var p="/api"`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("rewritten JS missing %q\noutput:\n%s", c, out)
		}
	}
	// Bare protocol-relative URLs are left alone in JS: they are also comment
	// and regex-literal syntax (e.g. /^https?:\/\//) and rewriting them
	// corrupts the code. The runtime shim handles real "//host" requests.
	if strings.Contains(out, "//api.claude.ai") == false {
		t.Errorf("protocol-relative URL should stay untouched in JS:\n%s", out)
	}
}

func TestRewriteAbsURLsPreservesNamespaceURI(t *testing.T) {
	p := testProxy(t)
	in := `createElementNS("http://www.w3.org/2000/svg", n); var u="https://schema.org/Thing"; var d="https://react.dev/errors/418"; var m="https://developer.mozilla.org/en-US/docs/Web"; fetch("https://example.com/x");`
	out := string(p.rewriteAbsURLs([]byte(in)))
	for _, keep := range []string{
		`"http://www.w3.org/2000/svg"`,
		`"https://schema.org/Thing"`,
		`"https://react.dev/errors/418"`,
		`"https://developer.mozilla.org/en-US/docs/Web"`,
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("namespace/doc URL %s should stay untouched:\n%s", keep, out)
		}
	}
	// ordinary external hosts are still rewritten
	if !strings.Contains(out, `"http://localhost:8080/example.com/x"`) {
		t.Errorf("ordinary host should still be rewritten:\n%s", out)
	}
}

func TestDefaultNamespaceHosts(t *testing.T) {
	p := testProxy(t)
	for _, host := range []string{"www.w3.org", "w3.org", "schema.org", "react.dev", "developer.mozilla.org", "html.spec.whatwg.org"} {
		if p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = true, want false (namespace/doc host)", host)
		}
	}
	for _, host := range []string{"assets-proxy.anthropic.com", "example.com", "auth.openai.com"} {
		if !p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = false, want true", host)
		}
	}
	if got := p.rewriteURL("http://www.w3.org/2000/svg"); got != "http://www.w3.org/2000/svg" {
		t.Errorf("rewriteURL(w3.org) = %q, want unchanged", got)
	}
}

func TestNormalizePath(t *testing.T) {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	p := NewProxy(Config{OwnDomain: own, Target: tgt, RootFallback: true})
	cases := []struct {
		in, want string
		rewrite  bool
	}{
		{"/https://localhost:8080/chatgpt.com//cdn/assets/x.css", "/chatgpt.com/cdn/assets/x.css", true},
		{"/https://localhost:8080/cdn/assets/x.css", "/cdn/assets/x.css", true},
		{"/https://api.example.com/v1/test.js", "/api.example.com/v1/test.js", true},
		{"/http://api.example.com//v1/t.js", "/api.example.com/v1/t.js", true},
		{"/https://example.com", "/example.com/", true},
		{"/chatgpt.com/cdn/assets/x.css", "", false},
		{"/cdn/assets/x.css", "", false},
		{"/https://hcaptcha.com/x", "", false}, // direct domain stays unnormalized
	}
	for _, c := range cases {
		got, ok := p.normalizePath(c.in)
		if ok != c.rewrite {
			t.Errorf("normalizePath(%q) ok = %v, want %v", c.in, ok, c.rewrite)
			continue
		}
		if got != c.want {
			t.Errorf("normalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCollapsePathSlashes(t *testing.T) {
	cases := map[string]string{
		"/chatgpt.com//cdn/x": "/chatgpt.com/cdn/x",
		"//cdn/assets/x":      "/cdn/assets/x",
		"/a/b/c":              "/a/b/c",
		"/a//b///c":           "/a/b/c",
		"/":                   "/",
		"":                    "",
	}
	for in, want := range cases {
		if got := collapsePathSlashes(in); got != want {
			t.Errorf("collapsePathSlashes(%q) = %q, want %q", in, got, want)
		}
	}
}
func TestRewriteAbsURLsPreservesRegexLiteral(t *testing.T) {
	p := testProxy(t)
	in := `/^https?:\/\//.test(t) ? window.location.replace(t) : s.replace(t); var u="https://claude.ai/x";`
	out := string(p.rewriteAbsURLs([]byte(in)))
	if !strings.Contains(out, `/^https?:\/\//.test(t)`) {
		t.Errorf("regex literal corrupted:\n%s", out)
	}
	if !strings.Contains(out, `"http://localhost:8080/claude.ai/x"`) {
		t.Errorf("string URL not rewritten:\n%s", out)
	}
}

func TestIsProxyHost(t *testing.T) {
	p := testProxy(t)
	cases := []struct {
		host string
		want bool
	}{
		{"claude.ai", true},
		{"api.claude.ai", true},
		{"a.b.claude.ai", true},
		{"example.com", false},
		{"claude.ai.evil.com", false},
		{"evilclaude.ai", false},
		{"", false},
	}
	for _, c := range cases {
		if got := p.isProxyHost(c.host); got != c.want {
			t.Errorf("isProxyHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestRegistrableDomainMatching(t *testing.T) {
	p := testProxy(t)
	if p.registrable != "" {
		t.Fatalf("claude.ai registrable = %q, want empty (already registrable)", p.registrable)
	}
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://www.wikipedia.org")
	q := NewProxy(Config{OwnDomain: own, Target: tgt})
	if q.registrable != "wikipedia.org" {
		t.Fatalf("www.wikipedia.org registrable = %q, want wikipedia.org", q.registrable)
	}
	for _, host := range []string{"en.wikipedia.org", "api.wikipedia.org", "wikipedia.org"} {
		if !q.isProxyHost(host) {
			t.Errorf("isProxyHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"evil.org", "wikipedia.org.evil.com", "127.0.0.1"} {
		if q.isProxyHost(host) {
			t.Errorf("isProxyHost(%q) = true, want false", host)
		}
	}
}

func TestRewriteURLAnyHost(t *testing.T) {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	p := NewProxy(Config{OwnDomain: own, Target: tgt, ExtraDomains: []string{"openai.com"}})
	cases := []struct{ in, want string }{
		{"https://auth.openai.com/log-in/password", "http://localhost:8080/auth.openai.com/log-in/password"},
		{"https://openai.com/x", "http://localhost:8080/openai.com/x"},
		{"https://help.openai.com/a/b?q=1", "http://localhost:8080/help.openai.com/a/b?q=1"},
		{"//auth.openai.com/log-in", "http://localhost:8080/auth.openai.com/log-in"},
		{"https://chatgpt.com/auth/start", "http://localhost:8080/chatgpt.com/auth/start"},
		{"https://evilopenai.com/x", "http://localhost:8080/evilopenai.com/x"},
		{"https://openai.com.evil.com/x", "http://localhost:8080/openai.com.evil.com/x"},
		{"https://example.com/x", "http://localhost:8080/example.com/x"},
	}
	for _, c := range cases {
		if got := p.rewriteURL(c.in); got != c.want {
			t.Errorf("rewriteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsProxyHostExtraDomain(t *testing.T) {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	p := NewProxy(Config{OwnDomain: own, Target: tgt, ExtraDomains: []string{"openai.com"}})
	for _, host := range []string{"openai.com", "auth.openai.com", "chatgpt.com"} {
		if !p.isProxyHost(host) {
			t.Errorf("isProxyHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"evil.com", "openai.com.evil.com"} {
		if p.isProxyHost(host) {
			t.Errorf("isProxyHost(%q) = true, want false", host)
		}
	}
}

func TestRewriteSetCookie(t *testing.T) {
	p := testProxy(t)
	cases := []struct{ in, want string }{
		{"session=abc; Domain=.claude.ai; Path=/", "session=abc; Path=/claude.ai/"},
		{"session=abc; Path=/foo", "session=abc; Path=/claude.ai/foo"},
		{"session=abc", "session=abc; Path=/claude.ai/"},
		{"Domain=.claude.ai; session=abc", "session=abc; Path=/claude.ai/"},
	}
	for _, c := range cases {
		if got := p.rewriteSetCookie(c.in, ""); got != c.want {
			t.Errorf("rewriteSetCookie(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestShimClickRewriteInPlace verifies the runtime shim rewrites an anchor's
// href attribute in place on click instead of force-navigating. SPA links
// (e.g. ChatGPT conversation list) must keep their client-side navigation;
// hijacking them with window.location.href turns every click into a full page
// reload. Plain links still navigate normally because default is not prevented.
func TestShimClickRewriteInPlace(t *testing.T) {
	p := testProxyExtra(t)
	shim := p.runtimeShimScript()
	i := strings.Index(shim, `document.addEventListener("click"`)
	if i < 0 {
		t.Fatal("click handler not found in shim")
	}
	click := shim[i:]
	for _, want := range []string{
		`a.setAttribute("href",p)`,
	} {
		if !strings.Contains(click, want) {
			t.Errorf("click handler missing %q", want)
		}
	}
	for _, bad := range []string{
		`e.preventDefault();`,
		`window.location.href=p;`,
		`window.open(p);`,
	} {
		if strings.Contains(click, bad) {
			t.Errorf("click handler must not %q", bad)
		}
	}
}

// TestShimCrossHostNavigation verifies the runtime shim converts a client-side
// history navigation that crosses proxied hosts (e.g. auth.openai.com page
// pushing the chatgpt.com callback URL) into a real full-page navigation. In
// the real world such a jump is cross-origin and always loads a new document;
// on the proxy domain both hosts share one origin, so without this the SPA
// would just change the URL and render its own fallback.
func TestShimCrossHostNavigation(t *testing.T) {
	p := testProxyExtra(t)
	shim := p.runtimeShimScript()
	for _, want := range []string{
		"function hostPrefix(p)",
		"function crossHostNav(p)",
		"if(crossHostNav(p)){window.location.href=p;return;}",
	} {
		if !strings.Contains(shim, want) {
			t.Errorf("shim missing %q", want)
		}
	}
	// crossHostNav must appear in both the pushState and replaceState wrappers.
	if strings.Count(shim, "if(crossHostNav(p)){window.location.href=p;return;}") != 2 {
		t.Errorf("crossHostNav forced navigation not wired into both history wrappers")
	}
}

func TestRewriteAbsURLsWSS(t *testing.T) {
	p := testProxyExtra(t)
	in := []byte(`{"websocket_url":"wss://ws.claude.ai/p3/ws/user/x?verify=a%252Bb","img":"https://claude.ai/a.png","rel":"//api.claude.ai/b"}`)
	out := string(p.rewriteAbsURLs(in))
	for _, want := range []string{
		`wss://localhost:8080/ws.claude.ai/p3/ws/user/x?verify=a%252Bb`,
		`http://localhost:8080/claude.ai/a.png`,
		`"rel":"//api.claude.ai/b"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rewriteAbsURLs output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `wss:https://`) || strings.Contains(out, `https//localhost`) {
		t.Errorf("wss URL mangled:\n%s", out)
	}
}

func TestRewriteURLInWSS(t *testing.T) {
	p := testProxyExtra(t)
	cases := []struct{ in, want string }{
		{"wss://ws.claude.ai/p3/ws/user/x", "wss://localhost:8080/ws.claude.ai/p3/ws/user/x"},
		{"ws://api.claude.ai/p3/ws", "ws://localhost:8080/api.claude.ai/p3/ws"},
		{"wss://example.com/x", "wss://localhost:8080/example.com/x"},
	}
	for _, c := range cases {
		if got := p.rewriteURLIn(c.in, ""); got != c.want {
			t.Errorf("rewriteURLIn(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
func TestLooksLikeHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"assets-proxy.anthropic.com", true},
		{"newassets.hcaptcha.com", true},
		{"fb2298ec24f2.w.hcaptcha.com", true},
		{"claude.ai", true},
		{"api.127.0.0.1:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8443", true},
		{"example.com:443", true},
		{"a.b", false},
		{"robots.txt", false},
		{"index.html", false},
		{"app.js", false},
		{"site.json", false},
		{"v1.2", false},
		{"en-US", false},
		{".well-known", false},
		{"localhost", false},
		{"", false},
		{"under_score.com", false},
	}
	for _, c := range cases {
		if got := looksLikeHost(c.in); got != c.want {
			t.Errorf("looksLikeHost(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestShouldProxyHost(t *testing.T) {
	p := testProxy(t)
	p.directDomains = append(p.directDomains, "hcaptcha.com")
	for _, host := range []string{"example.com", "assets-proxy.anthropic.com"} {
		if !p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"hcaptcha.com", "api.hcaptcha.com", "newassets.hcaptcha.com", "foo.hcaptcha.com", "localhost:8080"} {
		if p.shouldProxyHost(host) {
			t.Errorf("shouldProxyHost(%q) = true, want false", host)
		}
	}
}
func TestDefaultDirectDomains(t *testing.T) {
	p := testProxy(t)
	if p.shouldProxyHost("newassets.hcaptcha.com") || p.shouldProxyHost("api.hcaptcha.com") {
		t.Error("hcaptcha.com should be direct by default")
	}
	if got := p.rewriteURL("https://newassets.hcaptcha.com/1.11.0/hcaptcha.js"); got != "https://newassets.hcaptcha.com/1.11.0/hcaptcha.js" {
		t.Errorf("hcaptcha URL should stay direct, got %q", got)
	}
	if !p.shouldProxyHost("assets-proxy.anthropic.com") {
		t.Error("anthropic assets should still be proxied")
	}
}

// TestShimTemplateBalanced guards against brace-imbalance regressions in the
// injected runtime shim: the whole script is wrapped in an IIFE and every
// try/catch pair is balanced, so a stray brace would silently disable the
// entire shim (it fails to parse in the browser).
func TestShimTemplateBalanced(t *testing.T) {
	shim := testProxy(t).runtimeShimScript()
	depth := 0
	for _, r := range shim {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth < 0 {
			t.Fatal("negative brace depth in shim")
		}
	}
	if depth != 0 {
		t.Fatalf("shim brace depth = %d, want 0", depth)
	}
}
