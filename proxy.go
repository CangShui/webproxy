package main

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ctxKey int

const (
	ctxKeyPageURL ctxKey = iota
	ctxKeyPrefix
)

// defaultDirectDomains are third-party hosts that must load straight from
// their real origin. hCaptcha's CDN rejects server-side (non-browser) fetches
// with 403/502, so proxying it would break the CAPTCHA; its proofs are bound
// to the site host (checksiteconfig already sends host=own-domain) and the
// widget is designed to run cross-origin.
var defaultDirectDomains = []string{"hcaptcha.com"}

// sentinelHost is the bot-protection host OpenAI sites use for their
// Sentinel anti-bot frame/SDK. It is routed (and its URLs rewritten) through
// the proxy like any other proxied host, so the frame's /backend-api/sentinel/
// requests stay on the own domain instead of leaking to the real host.
const sentinelHost = "sentinel.openai.com"

// Proxy reverse-proxies a target site (and its subdomains) under path
// prefixes on the own domain, rewriting URLs inside responses.
type Proxy struct {
	cfg            Config
	ownOrigin      string // e.g. https://example.com
	ownHost        string // e.g. example.com
	targetHost     string // e.g. claude.ai (may include port)
	targetHostname string // e.g. claude.ai
	targetScheme   string // e.g. https
	barePrefixes   []string
	extraDomains   []string
	directDomains  []string
	registrable    string
	transport      http.RoundTripper
	maxBody        int64
}

func NewProxy(cfg Config) *Proxy {
	p := &Proxy{
		cfg:            cfg,
		ownOrigin:      cfg.OwnDomain.Scheme + "://" + cfg.OwnDomain.Host,
		ownHost:        cfg.OwnDomain.Hostname(),
		targetHost:     cfg.Target.Host,
		targetHostname: cfg.Target.Hostname(),
		targetScheme:   cfg.Target.Scheme,
		barePrefixes:   cfg.BarePrefixes,
		extraDomains:   cfg.ExtraDomains,
		directDomains:  append(append([]string{}, cfg.DirectDomains...), defaultDirectDomains...),
		registrable:    registrableDomain(cfg.Target.Hostname()),
		maxBody:        64 << 20,
	}
	p.transport = newBrowserTransport()
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" || path == "/" {
		p.redirect(w, r, "/"+p.targetHost+"/")
		return
	}

	// Bare prefixes (e.g. /cdn-cgi/ used by Cloudflare) proxy straight to the
	// target host without a host prefix in the URL.
	for _, bp := range p.barePrefixes {
		if path == strings.TrimSuffix(bp, "/") || strings.HasPrefix(path, bp) {
			target := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: path}
			if r.URL.RawQuery != "" {
				target.RawQuery = r.URL.RawQuery
			}
			p.serveReverse(w, r, target, p.pageURL(r), bp)
			return
		}
	}

	host, rest := splitPathPrefix(path)

	// The Sentinel SDK computes its frame/API URLs from the script origin
	// ("origin + /backend-api/sentinel/"), which becomes a host-prefix-less
	// path on the own domain. Route those straight to sentinel.openai.com and
	// synthesize the frame document (Cloudflare blocks Go's own fetch of the
	// real frame.html with 404/403).
	if strings.HasPrefix(path, "/backend-api/sentinel/") {
		if strings.HasPrefix(path, "/backend-api/sentinel/frame.html") {
			p.serveSentinelFrame(w, r)
			return
		}
		target := &url.URL{Scheme: p.targetScheme, Host: sentinelHost, Path: path}
		if r.URL.RawQuery != "" {
			target.RawQuery = r.URL.RawQuery
		}
		p.serveReverse(w, r, target, p.pageURL(r), "/backend-api/sentinel/")
		return
	}

	// The Sentinel anti-bot frame is served through the proxy: Cloudflare
	// blocks automated browsers (and Go's own fetch) from loading the real
	// frame.html, so synthesize the tiny document. The frame runs on the own
	// origin, so its SDK and /backend-api/sentinel/req calls stay on the own
	// domain and never leak to the real host.
	if strings.EqualFold(host, sentinelHost) && strings.HasPrefix(rest, "/backend-api/sentinel/frame.html") {
		p.serveSentinelFrame(w, r)
		return
	}
	// All other sentinel.openai.com paths are proxied too (SDK script,
	// enforcement endpoint, ...), even if the host was listed as a direct
	// domain: proxying is what keeps the sentinel traffic on the own domain.
	if strings.EqualFold(host, sentinelHost) {
		target := &url.URL{Scheme: p.targetScheme, Host: sentinelHost, Path: rest}
		if r.URL.RawQuery != "" {
			target.RawQuery = r.URL.RawQuery
		}
		p.serveReverse(w, r, target, p.pageURL(r), "/"+sentinelHost+"/")
		return
	}

	if !p.isProxiedHostPrefix(host) {
		if p.cfg.RootFallback {
			// SPA mode: client-side routed apps read location.pathname, so
			// unprefixed paths (and their root-relative API calls) are proxied
			// straight to the target host.
			target := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: path}
			if r.URL.RawQuery != "" {
				target.RawQuery = r.URL.RawQuery
			}
			p.serveReverse(w, r, target, p.pageURL(r), "/"+p.targetHost+"/")
			return
		}
		http.NotFound(w, r)
		return
	}
	if rest == "" {
		p.redirect(w, r, "/"+host+"/")
		return
	}

	target := &url.URL{
		Scheme: p.targetScheme,
		Host:   host,
		Path:   rest,
	}
	if r.URL.RawQuery != "" {
		target.RawQuery = r.URL.RawQuery
	}

	p.serveReverse(w, r, target, p.pageURL(r), "/"+host+"/")
}

// redirect preserves any query string so challenge-style callbacks
// (e.g. /?__cf_chl_rt_tk=...) survive the redirect.
func (p *Proxy) redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.URL.RawQuery != "" {
		to += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// unrewriteURLParams restores URL-valued query parameters (redirect_uri etc.)
// that point at the proxy's own domain back to their real upstream form, so
// authorization servers validate the original values. Response-side rewriting
// keeps the browser on the proxy domain.
// rewriteRequestHeaders rewrites Origin and Referer from the own domain to
// the real upstream origins so the target's CORS/CSRF checks pass, and
// Access-Control-Allow-Origin is reflected back to the own domain on the way
// out. The app normally runs on the real target origin, so pages served
// through the proxy must look like they came from that origin.
func (p *Proxy) rewriteRequestHeaders(req *http.Request) {
	if o := req.Header.Get("Origin"); o != "" {
		if ou, err := url.Parse(o); err == nil && ou.Scheme != "" && strings.EqualFold(ou.Hostname(), p.ownHost) {
			req.Header.Set("Origin", p.realOrigin(req))
		}
	}
	if rf := req.Header.Get("Referer"); rf != "" {
		if nr := p.unrewriteReferer(req, rf); nr != rf {
			req.Header.Set("Referer", nr)
		}
	}
}

// unrewriteReferer restores a browser Referer to its real upstream form.
// Prefixed proxied URLs are handled by unrewriteURL. A Referer whose path has
// no host prefix means the SPA strip script removed the prefix from the
// address bar; the page's real host is then the request's own upstream host
// (e.g. a form on auth.openai.com posts to /auth.openai.com/log-in/password
// while the browser's Referer is just /log-in/password).
func (p *Proxy) unrewriteReferer(req *http.Request, raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	if u.Scheme != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return raw
		}
		if !strings.EqualFold(u.Hostname(), p.ownHost) {
			return raw
		}
	} else if !strings.HasPrefix(raw, "//") {
		return raw
	}
	host, _ := splitPathPrefix(u.Path)
	if p.isProxiedHostPrefix(host) {
		return p.unrewriteURL(raw)
	}
	// Stripped SPA path: the whole path belongs to the request's upstream
	// host, and the first segment is NOT a host prefix.
	nu := &url.URL{Scheme: p.targetScheme, Host: req.URL.Host, Path: u.Path}
	if u.RawQuery != "" {
		nu.RawQuery = u.RawQuery
	}
	if u.Fragment != "" {
		nu.Fragment = u.Fragment
	}
	return nu.String()
}

// realOrigin returns the upstream origin the browser's page would have,
// derived from the Referer page when possible (its host prefix identifies the
// real site), falling back to the request's own upstream host (correct for
// SPA pages whose address-bar path has been stripped of the host prefix).
func (p *Proxy) realOrigin(req *http.Request) string {
	if rf := req.Header.Get("Referer"); rf != "" {
		if u, err := url.Parse(rf); err == nil && strings.EqualFold(u.Hostname(), p.ownHost) {
			if host, _ := splitPathPrefix(u.Path); p.isProxiedHostPrefix(host) {
				return p.targetScheme + "://" + host
			}
		}
	}
	return p.targetScheme + "://" + req.URL.Host
}

// unrewriteURL converts a URL on the own domain back to its real upstream
// form. Host-prefixed paths (/chatgpt.com/...) map back to that host;
// unprefixed paths (root fallback) map to the target host.
func (p *Proxy) unrewriteURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	if u.Scheme != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return raw
		}
		if !strings.EqualFold(u.Hostname(), p.ownHost) {
			return raw
		}
	} else if !strings.HasPrefix(raw, "//") {
		return raw
	}
	host, rest := splitPathPrefix(u.Path)
	if p.isProxiedHostPrefix(host) {
		if rest == "" {
			rest = "/"
		}
		nu := &url.URL{Scheme: p.targetScheme, Host: host, Path: rest}
		if u.RawQuery != "" {
			nu.RawQuery = u.RawQuery
		}
		if u.Fragment != "" {
			nu.Fragment = u.Fragment
		}
		return nu.String()
	}
	nu := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: u.Path}
	if u.RawQuery != "" {
		nu.RawQuery = u.RawQuery
	}
	if u.Fragment != "" {
		nu.Fragment = u.Fragment
	}
	return nu.String()
}

// rewriteLocation rewrites a Location header for the proxy domain. Absolute
// and protocol-relative Locations pointing at proxied hosts are rewritten like
// any other URL. Root-relative Locations are prefixed with the host prefix of
// the page that received the redirect (pageURL), so /log-in/password returned
// by auth.openai.com stays on the /auth.openai.com/ prefix and works even when
// root fallback is disabled. Relative Locations are left untouched: browsers
// resolve them against the request URL, which is already proxied.
func (p *Proxy) rewriteLocation(raw, pageURL string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Scheme != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return raw
		}
		if p.shouldProxyHost(u.Host) {
			return p.rewriteURLParams(p.ownOrigin + "/" + u.Host + uriOf(u))
		}
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		if p.shouldProxyHost(u.Host) {
			return p.rewriteURLParams(p.ownOrigin + "/" + u.Host + uriOf(u))
		}
		return raw
	}
	if strings.HasPrefix(u.Path, "/") {
		if !p.isProxiedPath(u.Path) {
			if prefix := p.pageHostOf(pageURL); prefix != "" {
				return p.rewriteURLParams(p.ownOrigin + "/" + prefix + uriOf(u))
			}
		}
	}
	return raw
}

// linkHeaderURLRe matches the URL inside each <...> link-value of a Link
// header (RFC 8288). Comma-splitting the header is unsafe because URLs may
// contain commas, so each angle-bracketed URI is rewritten in place.
var linkHeaderURLRe = regexp.MustCompile(`<([^>]*)>`)

// rewriteLinkHeader rewrites every URL carried by a Link response header so
// preload/preconnect hints point at the proxy domain instead of leaking
// direct requests to real origins.
func (p *Proxy) rewriteLinkHeader(v, pageURL string) string {
	return linkHeaderURLRe.ReplaceAllStringFunc(v, func(m string) string {
		inner := strings.TrimSpace(m[1 : len(m)-1])
		return "<" + p.rewriteURLIn(inner, pageURL) + ">"
	})
}

func (p *Proxy) unrewriteURLParams(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	changed := false
	for k := range q {
		lk := strings.ToLower(k)
		base := strings.TrimSuffix(lk, "[]")
		if !urlParamsToRewrite[base] && !urlParamsToRewrite[lk] {
			continue
		}
		vals := q[k]
		for i, v := range vals {
			if nv := p.unrewriteAbsParam(v); nv != v {
				vals[i] = nv
				changed = true
			}
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// unrewriteAbsParam converts a URL on the own domain whose first path segment
// is a proxied host (e.g. https://example.com/chatgpt.com/api/auth/callback)
// back to the real upstream URL (https://chatgpt.com/api/auth/callback).
func (p *Proxy) unrewriteAbsParam(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return v
	}
	absolute := u.Scheme == "http" || u.Scheme == "https" || (u.Scheme == "" && strings.HasPrefix(v, "//"))
	if !absolute || !strings.EqualFold(u.Hostname(), p.ownHost) {
		return v
	}
	host, rest := splitPathPrefix(u.Path)
	if !p.isProxiedHostPrefix(host) {
		return v
	}
	if rest == "" {
		rest = "/"
	}
	nu := &url.URL{Scheme: p.targetScheme, Host: host, Path: rest}
	if u.RawQuery != "" {
		nu.RawQuery = u.RawQuery
	}
	if u.Fragment != "" {
		nu.Fragment = u.Fragment
	}
	return nu.String()
}

func (p *Proxy) pageURL(r *http.Request) string {
	u := p.ownOrigin + r.URL.Path
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	return u
}

func splitPathPrefix(path string) (host, rest string) {
	p := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i:]
	}
	return p, ""
}

// serveSentinelFrame serves a synthetic sentinel frame document. The real
// frame.html is a static one-liner that loads the versioned SDK; fetching it
// from the upstream through Go is blocked by Cloudflare (404/403), so we
// rebuild it pointing at the proxied SDK URL.
func (p *Proxy) serveSentinelFrame(w http.ResponseWriter, r *http.Request) {
	sv := r.URL.Query().Get("sv")
	if sv == "" || !regexp.MustCompile(`^[A-Za-z0-9._-]+$`).MatchString(sv) {
		sv = "latest"
	}
	// The versioned SDK is loaded from the sentinel host; when sentinelHost is
	// proxied (not listed as a direct domain) the HTML rewriter below turns
	// this into a proxied URL, so the SDK runs on the own origin and its
	// /backend-api/sentinel/req calls stay on the own domain.
	src := p.targetScheme + "://" + sentinelHost + "/sentinel/" + sv + "/sdk.js"
	body := []byte("<!DOCTYPE html><html><body><script src='" + src + "'></script></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Del("Content-Security-Policy")
	out := p.rewriteHTML(body, p.pageURL(r), "")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.WriteHeader(http.StatusOK)
	w.Write(out)
}

func (p *Proxy) serveReverse(w http.ResponseWriter, r *http.Request, target *url.URL, pageURL, pathPrefix string) {
	director := func(req *http.Request) {
		u := *target
		if s := p.unrewriteURLParams(u.String()); s != u.String() {
			if nu, err := url.Parse(s); err == nil {
				u = *nu
			}
		}
		req.URL = &u
		p.rewriteRequestHeaders(req)
		req.Host = target.Host
		req.Header.Set("Accept-Encoding", "identity")
		p.debugLogf("UPSTREAM %s %s host=%q proto=%s hdrs=%v", req.Method, req.URL.String(), req.Host, req.Proto, req.Header)
		ctx := context.WithValue(req.Context(), ctxKeyPageURL, pageURL)
		ctx = context.WithValue(ctx, ctxKeyPrefix, pathPrefix)
		*req = *req.WithContext(ctx)
	}
	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: p.transport,
		ModifyResponse: func(resp *http.Response) error {
			p.modifyResponse(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.debugLogf("UPSTREAM-ERR %s %s: %v", r.Method, r.URL.String(), err)
			http.Error(w, "502 Bad Gateway: "+err.Error(), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

func (p *Proxy) modifyResponse(resp *http.Response) {
	h := resp.Header
	for _, k := range []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Strict-Transport-Security",
		"X-Frame-Options",
	} {
		h.Del(k)
	}

	if loc := h.Get("Location"); loc != "" {
		pageURL, _ := ctxString(resp, ctxKeyPageURL)
		h.Set("Location", p.rewriteLocation(loc, pageURL))
	}

	// Link headers carry preload/preconnect hints (e.g. Cloudflare's
	// "Link: <https://assets-proxy.example.com/x.js>; rel=modulepreload").
	// Browsers fetch those URLs before the body is parsed, so unrewritten
	// hints leak direct requests to real origins. Rewrite every URL in them.
	if lk := h.Values("Link"); len(lk) > 0 {
		pageURL, _ := ctxString(resp, ctxKeyPageURL)
		h.Del("Link")
		for _, v := range lk {
			h.Add("Link", p.rewriteLinkHeader(v, pageURL))
		}
	}

	if acao := h.Get("Access-Control-Allow-Origin"); acao != "" && acao != "*" {
		origins := strings.Split(acao, ",")
		changed := false
		for i, o := range origins {
			o = strings.TrimSpace(o)
			if u, err := url.Parse(o); err == nil && u.Scheme != "" && p.shouldProxyHost(u.Hostname()) {
				origins[i] = p.ownOrigin
				changed = true
			}
		}
		if changed {
			h.Set("Access-Control-Allow-Origin", strings.Join(origins, ", "))
		}
	}

	if sc := h.Values("Set-Cookie"); len(sc) > 0 {
		prefix, _ := ctxString(resp, ctxKeyPrefix)
		if p.cfg.RootFallback {
			// In SPA mode the app runs at root semantics, so cookies must be
			// visible to both prefixed and unprefixed paths.
			prefix = "/"
		}
		h.Del("Set-Cookie")
		for _, c := range sc {
			h.Add("Set-Cookie", p.rewriteSetCookie(c, prefix))
		}
	}

	if resp.Body == nil || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return
	}
	if h.Get("Content-Encoding") != "" {
		return // compressed payloads are passed through untouched
	}
	ct := h.Get("Content-Type")
	if !isRewritable(ct) {
		return
	}

	pageURL, _ := ctxString(resp, ctxKeyPageURL)
	stripPrefix := ""
	if p.cfg.RootFallback {
		// Strip the host prefix for any proxied host page (target or extra
		// domain, e.g. auth.openai.com) so client-side routers match the
		// target's native routes and can intercept form submissions. Bare
		// prefixes like /cdn-cgi/ or /backend-api/sentinel/ are not host
		// prefixes and keep their path.
		if prefix, ok := ctxString(resp, ctxKeyPrefix); ok {
			if host := strings.TrimSuffix(strings.TrimPrefix(prefix, "/"), "/"); host != "" && p.isProxyHost(host) {
				stripPrefix = "/" + host
			}
		}
	}
	body := resp.Body
	transform := func(data []byte) []byte {
		switch {
		case strings.Contains(ct, "html"):
			return p.rewriteHTML(data, pageURL, stripPrefix)
		case strings.Contains(ct, "css"):
			return []byte(p.rewriteCSS(string(data)))
		default: // javascript / json
			return p.rewriteAbsURLs(data)
		}
	}
	resp.Body = &transformBody{rc: body, transform: transform, max: p.maxBody}
	h.Del("Content-Length")
}

func ctxString(resp *http.Response, key ctxKey) (string, bool) {
	if resp == nil || resp.Request == nil {
		return "", false
	}
	v, ok := resp.Request.Context().Value(key).(string)
	return v, ok
}

var (
	cookieDomainRe = regexp.MustCompile(`(?i);?\s*Domain\s*=\s*[^;]*`)
	cookiePathRe   = regexp.MustCompile(`(?i)(;\s*Path\s*=\s*)(/)([^;]*)`)
)

// rewriteSetCookie scopes cookies to the own domain and the proxied path
// prefix (e.g. /claude.ai/ or /cdn-cgi/).
func (p *Proxy) rewriteSetCookie(c, prefix string) string {
	if prefix == "" {
		prefix = "/" + p.targetHost + "/"
	}
	c = cookieDomainRe.ReplaceAllString(c, "")
	c = strings.TrimSpace(c)
	c = strings.TrimPrefix(c, ";")
	c = strings.TrimSpace(c)

	c = cookiePathRe.ReplaceAllStringFunc(c, func(m string) string {
		mm := cookiePathRe.FindStringSubmatch(m)
		return mm[1] + prefix + strings.TrimPrefix(mm[3], "/")
	})
	if !strings.Contains(strings.ToLower(c), "path=") {
		c += "; Path=" + prefix
	}
	return c
}

func isRewritable(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mt = strings.ToLower(mt)
	switch {
	case strings.Contains(mt, "html"):
		return true
	case mt == "text/css":
		return true
	case mt == "application/javascript", mt == "text/javascript", mt == "application/x-javascript":
		return true
	case mt == "application/json", mt == "text/json":
		return true
	case strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+javascript"):
		return true
	}
	return false
}

// transformBody buffers the whole (small) response, rewrites it, then serves
// the rewritten bytes. Oversized bodies are passed through unmodified.
type transformBody struct {
	rc        io.ReadCloser
	transform func([]byte) []byte
	max       int64
	done      bool
	head      []byte
	tail      io.ReadCloser
}

func (b *transformBody) Read(p []byte) (int, error) {
	if !b.done {
		b.done = true
		data, err := io.ReadAll(io.LimitReader(b.rc, b.max+1))
		_ = err
		if int64(len(data)) > b.max {
			b.head = data
			b.tail = b.rc
		} else {
			b.head = b.transform(data)
			b.tail = nil
			b.rc.Close()
		}
	}
	if len(b.head) > 0 {
		n := copy(p, b.head)
		b.head = b.head[n:]
		return n, nil
	}
	if b.tail != nil {
		return b.tail.Read(p)
	}
	return 0, io.EOF
}

func (b *transformBody) Close() error {
	if b.tail != nil {
		return b.tail.Close()
	}
	return b.rc.Close()
}

func (p *Proxy) debugLogf(format string, args ...any) {
	if os.Getenv("WEBPROXY_DEBUG") == "" {
		return
	}
	f, err := os.OpenFile("webproxy-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(time.Now().Format("15:04:05.000") + " " + fmt.Sprintf(format, args...) + "\n")
}
