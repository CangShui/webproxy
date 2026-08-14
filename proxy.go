package main

import (
	"compress/flate"
	"compress/gzip"
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

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
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

// defaultNamespaceHosts are hosts whose URLs are URI identifiers or pure
// documentation, not resources the site loads: XML namespace URIs
// (http://www.w3.org/2000/svg), schema URIs, spec references and error-doc
// links (React's https://react.dev/errors/...). Rewriting them inside JS
// breaks code that compares strings against the literal URI - React's SVG
// handling crashed when createElementNS received a rewritten xmlns value -
// and produces useless /host/ paths, so they are excluded for every target.
var defaultNamespaceHosts = []string{
	"w3.org",
	"schema.org",
	"react.dev",
	"whatwg.org",
	"ietf.org",
	"developer.mozilla.org",
}

// sentinelHost is the bot-protection host OpenAI sites use for their
// Sentinel anti-bot frame/SDK. It is routed (and its URLs rewritten) through
// the proxy like any other proxied host, so the frame's /backend-api/sentinel/
// requests stay on the own domain instead of leaking to the real host.
const sentinelHost = "sentinel.openai.com"

// chromeUserAgent is a current real Chrome UA used only as a fallback when the
// client sends no User-Agent at all, so the upstream does not flag the server
// as a scraper. A client-supplied UA is always forwarded untouched.
const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

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
	direct := append([]string{}, cfg.DirectDomains...)
	direct = append(direct, defaultDirectDomains...)
	direct = append(direct, defaultNamespaceHosts...)
	p := &Proxy{
		cfg:            cfg,
		ownOrigin:      cfg.OwnDomain.Scheme + "://" + cfg.OwnDomain.Host,
		ownHost:        cfg.OwnDomain.Hostname(),
		targetHost:     cfg.Target.Host,
		targetHostname: cfg.Target.Hostname(),
		targetScheme:   cfg.Target.Scheme,
		barePrefixes:   cfg.BarePrefixes,
		extraDomains:   cfg.ExtraDomains,
		directDomains:  direct,
		registrable:    registrableDomain(cfg.Target.Hostname()),
		maxBody:        64 << 20,
	}
	p.transport = newBrowserTransport(p.cfg.UpstreamProxy)
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" || path == "/" {
		if p.cfg.RootSite {
			target := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: "/"}
			p.serveReverse(w, r, target, p.pageURL(r), "/")
			return
		}
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

	// Client apps sometimes re-prefix an already-proxied absolute URL with the
	// origin, producing paths like /https://own/host/path (the embedded URL
	// may itself already carry the host prefix). Recover the canonical path
	// instead of 404ing on the "https:" segment.
	if np, ok := p.normalizePath(path); ok {
		path = np
		r.URL.Path = np
		if r.URL.RawPath != "" {
			r.URL.RawPath = ""
		}
	}

	host, rest := splitPathPrefix(path)

	// Same family of app bugs: /host//cdn/x - a host prefix followed by a
	// double slash (apps concatenate origins with absolute URLs). Collapse it
	// so the upstream receives the canonical path.
	if strings.HasPrefix(rest, "//") && p.isProxiedHostPrefix(host) {
		rest = collapsePathSlashes(rest)
		path = "/" + host + rest
		r.URL.Path = path
		if r.URL.RawPath != "" {
			r.URL.RawPath = ""
		}
	}

	// The Sentinel SDK computes its frame/API URLs from the script origin
	// ("origin + /backend-api/sentinel/"), which becomes a host-prefix-less
	// path on the own domain. Route those straight to sentinel.openai.com and
	// synthesize the frame document (Cloudflare blocks Go's own fetch of the
	// real frame.html with 404/403). This only applies in the default path-
	// prefixed mode: in root-site mode the target owns '/backend-api/sentinel/*'
	// (e.g. chatgpt.com's own chat-requirements/prepare), so those paths must
	// reach the target, not sentinel.openai.com.
	if !p.cfg.RootSite && strings.HasPrefix(path, "/backend-api/sentinel/") {
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
		// host:port segments whose hostname can never be routed back
		// (localhost:3000, 127.0.0.1:PORT) are dev artifacts, not SPA routes;
		// 404 them instead of falling back to the target.
		if strings.Contains(host, ":") && isUnroutableHost(host) {
			http.NotFound(w, r)
			return
		}
		if p.cfg.RootFallback {
			// SPA mode: client-side routed apps read location.pathname, so
			// unprefixed paths (and their root-relative API calls) are proxied
			// straight to the target host. In root-site mode the target lives
			// at the own-domain root, so the fallback prefix is "/".
			prefix := "/" + p.targetHost + "/"
			if p.cfg.RootSite {
				prefix = "/"
			}
			target := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: path}
			if r.URL.RawQuery != "" {
				target.RawQuery = r.URL.RawQuery
			}
			p.serveReverse(w, r, target, p.pageURL(r), prefix)
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
	// Root-site mode: a root path with no proxied-host prefix belongs to the
	// target host (served at the own-domain root), so restore it to upstream.
	if p.cfg.RootSite {
		nu := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: u.Path}
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
			return p.rewriteURLParams(p.ownURLFor(u.Host, uriOf(u)))
		}
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		if p.shouldProxyHost(u.Host) {
			return p.rewriteURLParams(p.ownURLFor(u.Host, uriOf(u)))
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
	// rewriteURLIn expects the host prefix of the current page (e.g.
	// "chatgpt.com"), not the full page URL: feeding it the page URL would
	// insert the whole /host/path/ segment into every rewritten Link URL.
	pageHost := p.pageHostOf(pageURL)
	return linkHeaderURLRe.ReplaceAllStringFunc(v, func(m string) string {
		inner := strings.TrimSpace(m[1 : len(m)-1])
		return "<" + p.rewriteURLIn(inner, pageHost) + ">"
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
		// Root-site mode: a root URL with no host prefix maps to the target
		// host (served at the own-domain root).
		if p.cfg.RootSite {
			path := u.Path
			if path == "" {
				path = "/"
			}
			nu := &url.URL{Scheme: p.targetScheme, Host: p.targetHost, Path: path}
			if u.RawQuery != "" {
				nu.RawQuery = u.RawQuery
			}
			if u.Fragment != "" {
				nu.Fragment = u.Fragment
			}
			return nu.String()
		}
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

// embeddedURLPathRe matches request paths that embed an absolute URL as their
// first path segment, e.g. /https://host/path. Some client apps concatenate
// the origin with an already-absolute URL, producing both the plain
// /https://api.example.com/v1/x form and the re-prefixed
// /https://own-host/host-prefix//cdn/x form.
var embeddedURLPathRe = regexp.MustCompile("(?i)^/(https?://.*)$")

// normalizePath recovers the canonical proxied path from a path that embeds
// an absolute URL as its first segment. Embedded URLs on the own domain keep
// their inner path (which may itself carry a host prefix); external hosts get
// the standard /host/path form. Duplicate slashes are collapsed in both
// cases. It returns the canonical path and true when a rewrite happened.
func (p *Proxy) normalizePath(path string) (string, bool) {
	m := embeddedURLPathRe.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	u, err := url.Parse(m[1])
	if err != nil || u.Host == "" {
		return "", false
	}
	upath := u.Path
	if upath == "" {
		upath = "/"
	}
	upath = collapsePathSlashes(upath)
	if strings.EqualFold(u.Hostname(), p.ownHost) {
		return upath, true
	}
	if !p.shouldProxyHost(u.Host) {
		return "", false
	}
	return "/" + u.Host + upath, true
}

// collapsePathSlashes collapses runs of duplicate "/" in a URL path, so paths
// like /host//cdn/x (produced by apps that concatenate origins with absolute
// URLs) route correctly.
func collapsePathSlashes(path string) string {
	if !strings.Contains(path, "//") {
		return path
	}
	var b strings.Builder
	b.Grow(len(path))
	prevSlash := false
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b.WriteByte(c)
	}
	return b.String()
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
	out := p.rewriteHTML(body, p.pageURL(r))
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
		// Preserve the client's original path escaping. Go re-encodes URL
		// characters such as parentheses ( -> %28) when it serializes a
		// freshly built URL, but Cloudflare rejects the encoded form with
		// 403 "Invalid URL" on routes like /cdn/assets/(_lang).js. Forward
		// the browser's exact escaped path so special characters stay
		// byte-for-byte identical. The candidate is only used when it is a
		// valid encoding of the upstream path (prefix stripping only applies
		// to handlers whose target path is the prefix suffix).
		if r.URL.RawPath != "" {
			raw := r.URL.EscapedPath()
			esc := raw
			switch {
			case pathPrefix != "" && strings.HasPrefix(raw, pathPrefix):
				esc = "/" + strings.TrimPrefix(raw[len(pathPrefix):], "/")
			case strings.HasPrefix(raw, "/"):
				esc = raw
			}
			if dec, err := url.PathUnescape(esc); err == nil && dec == u.Path {
				u.RawPath = esc
			}
		}
		req.URL = &u
		p.rewriteRequestHeaders(req)
		req.Host = target.Host
		// Pass the client's Accept-Encoding through instead of forcing
		// "identity": forcing identity is a strong datacenter/scraper signal.
		// Compressed responses are transparently decompressed, rewritten, and
		// served as identity in modifyResponse (see below).
		//
		// If the client sent no User-Agent (e.g. scripts, some clients), fall
		// back to a real Chrome UA so the upstream does not treat the server
		// as a bot. A present UA (including the empty-string placeholder from
		// curl) is left untouched.
		if strings.TrimSpace(req.Header.Get("User-Agent")) == "" {
			req.Header.Set("User-Agent", chromeUserAgent)
		}
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
	if resp.Request != nil {
		p.debugLogf("UPSTREAM-RESP %s %s -> %d Location=%q", resp.Request.Method, resp.Request.URL.String(), resp.StatusCode, h.Get("Location"))
	}
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
	ct := h.Get("Content-Type")
	if !isRewritable(ct) {
		return // non-rewritable payloads pass through untouched (with their encoding)
	}
	pageURL, _ := ctxString(resp, ctxKeyPageURL)
	body := resp.Body
	// Accept-Encoding now passes through, so rewritable content may arrive
	// compressed (gzip/deflate/br/zstd). Decompress it, rewrite it, then serve
	// the result as identity: the browser accepts identity fine, and we avoid
	// re-compressing every response. Unknown/unhandled encodings pass through
	// untouched rather than corrupting the body.
	if enc := strings.ToLower(h.Get("Content-Encoding")); enc != "" {
		dec, err := decompressReader(enc, body)
		if err != nil {
			// Unexpected encoding; pass the compressed body through untouched.
			return
		}
		body = dec
	} else {
		h.Del("Content-Encoding")
	}
	transform := func(data []byte) []byte {
		switch {
		case strings.Contains(ct, "html"):
			return p.rewriteHTML(data, pageURL)
		case strings.Contains(ct, "css"):
			return []byte(p.rewriteCSS(string(data)))
		default: // javascript / json
			return p.rewriteAbsURLs(data)
		}
	}
	// If we decompressed, serve the rewritten bytes as identity.
	if strings.ToLower(h.Get("Content-Encoding")) != "" {
		h.Del("Content-Encoding")
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

// decompressReader wraps rc with the appropriate decompressor for enc
// (lower-cased Content-Encoding: gzip, deflate, br, zstd, x-gzip). It returns
// a reader that yields the decoded bytes. Brotli and zstd are supported via
// the same libraries the x/net chain already vendors, so no new dependency is
// introduced. An empty/unknown encoding yields an error so the caller can pass
// the compressed body through untouched.
func decompressReader(enc string, rc io.ReadCloser) (io.ReadCloser, error) {
	switch enc {
	case "gzip", "x-gzip":
		return &readCloser{Reader: mustGzip(rc)}, nil
	case "deflate":
		fr := flate.NewReader(rc)
		return &readCloser{Reader: fr, closer: rc}, nil
	case "br":
		return &brotliReadCloser{rc: rc}, nil
	case "zstd":
		zr, err := zstd.NewReader(rc)
		if err != nil {
			rc.Close()
			return nil, err
		}
		return &zstdReadCloser{dec: zr, rc: rc}, nil
	}
	// Unknown encoding: let the caller hand it through untouched.
	return nil, fmt.Errorf("unsupported content-encoding %q", enc)
}

func mustGzip(rc io.ReadCloser) io.ReadCloser {
	gz, err := gzip.NewReader(rc)
	if err != nil {
		rc.Close()
		return &emptyReadCloser{}
	}
	return &readCloser{Reader: gz, closer: rc}
}

// readCloser adapts an io.Reader into an io.ReadCloser that also closes rc.
type readCloser struct {
	io.Reader
	closer io.ReadCloser
}

func (r *readCloser) Close() error {
	rc := r.closer
	if rc != nil {
		return rc.Close()
	}
	return nil
}

// brotliReadCloser wraps a brotli reader over rc.
type brotliReadCloser struct {
	rc io.ReadCloser
	br *brotli.Reader
}

func (b *brotliReadCloser) Read(p []byte) (int, error) {
	if b.br == nil {
		b.br = brotli.NewReader(b.rc)
	}
	return b.br.Read(p)
}

func (b *brotliReadCloser) Close() error { return b.rc.Close() }

// zstdReadCloser wraps a zstd decoder over rc.
type zstdReadCloser struct {
	dec  *zstd.Decoder
	rc   io.ReadCloser
	done bool
}

func (z *zstdReadCloser) Read(p []byte) (int, error) {
	n, err := z.dec.Read(p)
	if err == io.EOF && !z.done {
		z.done = true
	}
	return n, err
}

func (z *zstdReadCloser) Close() error {
	z.dec.Close()
	return z.rc.Close()
}

// emptyReadCloser yields EOF and closes nothing.
type emptyReadCloser struct{}

func (e *emptyReadCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (e *emptyReadCloser) Close() error             { return nil }

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
