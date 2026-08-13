package main

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
)

// urlAttrs are HTML attributes whose value is a URL that should be rewritten.
var urlAttrs = map[string]bool{
	"href":              true,
	"src":               true,
	"action":            true,
	"poster":            true,
	"formaction":        true,
	"cite":              true,
	"background":        true,
	"data":              true,
	"xlink:href":        true,
	"data-src":          true,
	"data-href":         true,
	"data-url":          true,
	"data-original":     true,
	"data-srcset":       true,
	"data-poster":       true,
	"data-lazy-src":     true,
	"data-src-original": true,
	"data-echo":         true,
	"data-thumb":        true,
	"data-image":        true,
}

var (
	cssURLRe      = regexp.MustCompile(`(?i)url\(\s*(?:'([^']*)'|"([^"]*)"|([^)'"]+))\s*\)`)
	cssImportRe   = regexp.MustCompile(`(?i)(@import\s+)(['"])([^'"]+)(['"])`)
	metaRefreshRe = regexp.MustCompile(`(?i)(url\s*=\s*)(['"]?)([^'";]+)`)
	// absURLRe matches absolute URLs only (no bare //): inside JavaScript a
	// "//" is also a comment or regex-literal fragment, and rewriting it
	// corrupts code such as /^https?:\/\//. Protocol-relative URLs in JS/JSON
	// are rare and are still handled at runtime by the injected shim.
	absURLRe = regexp.MustCompile(`(?i)(wss?://|https?://)([a-zA-Z0-9\-._~]+(?::[0-9]+)?)([^'"\s<>` + "`" + `,;)\]}]*)`)
)

// isProxyHost reports whether host is the target host, one of its subdomains,
// or a sibling under the target's registrable domain (e.g. with target
// www.example.com, api.example.com is also proxied).
func (p *Proxy) isProxyHost(host string) bool {
	if host == "" {
		return false
	}
	hostname := host
	if i := strings.LastIndex(host, ":"); i >= 0 {
		hostname = host[:i]
	}
	// Direct domains are never proxied (e.g. sentinel.openai.com), even when
	// they fall under a proxied registrable domain: their bot-protection
	// proofs are bound to the real origin, so they must load directly.
	for _, d := range p.directDomains {
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return false
		}
	}
	if hostname == p.targetHostname || strings.HasSuffix(hostname, "."+p.targetHostname) {
		return true
	}
	if p.registrable != "" && (hostname == p.registrable || strings.HasSuffix(hostname, "."+p.registrable)) {
		return true
	}
	for _, d := range p.extraDomains {
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return true
		}
	}
	return false
}

// registrableDomain returns the registrable domain (eTLD+1) of host, or "" if
// host is an IP address, single-label, or already the registrable domain.
func registrableDomain(host string) string {
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || reg == "" || reg == host {
		return ""
	}
	return reg
}

// hostnameOnly strips a :port suffix from host.
func hostnameOnly(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

// commonFileExtRe matches last labels that are far more likely to be file
// extensions than TLDs (robots.txt, index.html, app.js, ...), so legitimate
// site paths are not mistaken for host prefixes.
var commonFileExtRe = regexp.MustCompile(`(?i)^(a?png|aspx?|avif|bmp|cgi|cfm|css|csv|do|docx?|eot|gif|gz|htm[l]?|ico|jpe?g|jsp|js|json|map|md|mjs|cjs|mov|mp3|mp4|otf|pdf|php|pl|png|ppt[x]?|py|rar|rss|shtml|svg|tar|tex|ts|ttf|txt|wav|wasm|webmanifest|webm|webp|woff2?|xlsx?|xml|zip)$`)

// looksLikeHost reports whether s plausibly names a real host (a registered
// domain with a TLD-like last label, an IP, or host:port) as opposed to a path
// segment such as robots.txt or v1.2. The proxy uses it to tell host prefixes
// apart from ordinary site paths.
func looksLikeHost(s string) bool {
	h := strings.ToLower(strings.TrimSpace(s))
	if h == "" {
		return false
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		if port == "" {
			return false
		}
		for _, c := range port {
			if c < '0' || c > '9' {
				return false
			}
		}
		h = h[:i]
		if h == "" {
			return false
		}
	}
	if net.ParseIP(h) != nil {
		return true
	}
	// Subdomains of an IP literal (api.127.0.0.1) are valid hostnames too.
	if i := strings.IndexByte(h, '.'); i >= 0 && i+1 < len(h) && net.ParseIP(h[i+1:]) != nil {
		return true
	}
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") ||
		strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	last := h[strings.LastIndexByte(h, '.')+1:]
	if len(last) < 2 || len(last) > 24 {
		return false
	}
	for _, c := range last {
		if !(c >= 'a' && c <= 'z') {
			return false
		}
	}
	return !commonFileExtRe.MatchString(last)
}

// shouldProxyHost reports whether absolute URLs pointing at host should be
// rewritten through the proxy. By default every external host is proxied
// (catch-all); only the own domain and explicitly direct domains are left
// alone.
func (p *Proxy) shouldProxyHost(host string) bool {
	if host == "" {
		return false
	}
	// The own domain is matched by host:port, so a target on the same
	// hostname but a different port (e.g. 127.0.0.1 in tests) is still
	// proxied. A bare hostname with no port is always the own domain.
	if strings.EqualFold(host, p.cfg.OwnDomain.Host) {
		return false
	}
	hostname := hostnameOnly(host)
	if hostname == "" || (strings.EqualFold(hostname, p.ownHost) && !strings.Contains(host, ":")) {
		return false
	}
	for _, d := range p.directDomains {
		if hostname == d || strings.HasSuffix(hostname, "."+d) {
			return false
		}
	}
	return true
}

// isHostPrefix reports whether host can act as a host prefix in a proxied URL:
// a known proxied host (target, its subdomains/siblings, extra domains) or a
// plausible hostname.
func (p *Proxy) isHostPrefix(host string) bool {
	if host == "" {
		return false
	}
	return p.isProxyHost(host) || looksLikeHost(host)
}

// isProxiedHostPrefix reports whether host is a host prefix that is allowed to
// route through the proxy (host-like or known, and not direct/own).
func (p *Proxy) isProxiedHostPrefix(host string) bool {
	return p.isHostPrefix(host) && p.shouldProxyHost(host)
}

func (p *Proxy) isProxiedPath(path string) bool {
	first := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(first, '/'); i >= 0 {
		first = first[:i]
	}
	return p.isProxiedHostPrefix(first)
}

// rewriteURL rewrites a URL found in an HTML/CSS/JS document so that it goes
// through this proxy. Every external absolute URL is proxied (catch-all);
// only relative URLs are left alone (they resolve against the injected
// <base> tag). Use -direct-domain to keep specific hosts unproxied.
func (p *Proxy) rewriteURL(raw string) string {
	return p.rewriteURLIn(raw, "")
}

// pageHostOf returns the proxied host prefix embedded in a page URL served by
// the proxy (e.g. "auth.openai.com" for https://example.com/auth.openai.com/x),
// or "" when the page has no host prefix (root fallback) or the first path
// segment is not a proxied host.
func (p *Proxy) pageHostOf(pageURL string) string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	host, _ := splitPathPrefix(u.Path)
	if host == "" || !p.isProxiedHostPrefix(host) {
		return ""
	}
	return host
}

// rewriteURLIn rewrites a URL like rewriteURL, but resolves root-relative
// paths against pageHost (the host prefix of the current page) instead of the
// default target host. Pages served from proxied extra domains (e.g.
// auth.openai.com) must keep their root-relative links and form actions on the
// same upstream host, so /log-in/password on auth.openai.com must become
// /auth.openai.com/log-in/password, not /chatgpt.com/log-in/password.
func (p *Proxy) rewriteURLIn(raw, pageHost string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Scheme != "" {
		switch u.Scheme {
		case "http", "https":
			if p.shouldProxyHost(u.Host) {
				return p.rewriteURLParams(p.ownOrigin + "/" + u.Host + uriOf(u))
			}
		case "ws", "wss":
			// WebSocket URLs keep their scheme and move the host into the own
			// domain's host prefix: wss://ws.chatgpt.com/x -> wss://own/x.
			if p.shouldProxyHost(u.Host) {
				return u.Scheme + "://" + p.cfg.OwnDomain.Host + "/" + u.Host + uriOf(u)
			}
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
		if p.isProxiedPath(u.Path) {
			return raw
		}
		host := pageHost
		if host == "" {
			host = p.targetHost
		}
		return p.rewriteURLParams(p.ownOrigin + "/" + host + uriOf(u))
	}
	return raw
}

func uriOf(u *url.URL) string {
	s := u.Path
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		s += "#" + u.Fragment
	}
	return s
}

// rewriteHTML rewrites URLs inside an HTML document and injects a <base> tag so
// that root-relative and relative URLs resolve through the proxy. pageURL is
// the proxied URL of the current document. stripPrefix, when non-empty, is the
// path prefix to remove from the page URL at runtime (SPA mode), so client-side
// routers see the target's native paths.
func (p *Proxy) rewriteHTML(body []byte, pageURL, stripPrefix string) []byte {
	pageHost := p.pageHostOf(pageURL)
	z := html.NewTokenizer(bytes.NewReader(body))
	var out bytes.Buffer
	var head bytes.Buffer
	buffering := true
	headOpenEnd := -1
	sawBase := false
	inStyle := false
	inScript := false

	write := func(b []byte) {
		if buffering {
			head.Write(b)
		} else {
			out.Write(b)
		}
	}

	flushHead := func() {
		if !buffering {
			return
		}
		var injected string
		if !sawBase && pageURL != "" {
			injected += `<base href="` + html.EscapeString(pageURL) + `">`
		}
		if stripPrefix != "" {
			// Strip before the runtime shim installs its history hooks, so
			// client-side routers see the target's native paths and can
			// intercept form submissions (which attach the sentinel headers).
			injected += `<script>` + spaStripScript(stripPrefix) + `</script>`
		}
		injected += `<script>` + p.runtimeShimScript() + `</script>`
		if injected != "" {
			if headOpenEnd >= 0 {
				h := head.Bytes()
				var nb bytes.Buffer
				nb.Write(h[:headOpenEnd])
				nb.WriteString(injected)
				nb.Write(h[headOpenEnd:])
				out.Write(nb.Bytes())
			} else {
				out.WriteString(injected)
				out.Write(head.Bytes())
			}
		} else {
			out.Write(head.Bytes())
		}
		head.Reset()
		buffering = false
	}

	emitTag := func(tag string, attrs []html.Attribute, selfClosing bool) {
		var tmp bytes.Buffer
		tmp.WriteByte('<')
		tmp.WriteString(tag)
		for _, a := range attrs {
			tmp.WriteByte(' ')
			tmp.WriteString(a.Key)
			if a.Val != "" {
				tmp.WriteString(`="`)
				tmp.WriteString(html.EscapeString(a.Val))
				tmp.WriteByte('"')
			}
		}
		if selfClosing {
			tmp.WriteString("/>")
		} else {
			tmp.WriteByte('>')
		}
		write(tmp.Bytes())
	}

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			flushHead()
			return out.Bytes()

		case html.DoctypeToken, html.CommentToken:
			write(z.Raw())

		case html.StartTagToken, html.SelfClosingTagToken:
			rawName, hasAttr := z.TagName()
			tag := strings.ToLower(string(rawName))
			attrs := make([]html.Attribute, 0, 4)
			if hasAttr {
				for {
					k, v, more := z.TagAttr()
					attrs = append(attrs, html.Attribute{Key: string(k), Val: string(v)})
					if !more {
						break
					}
				}
			}

			// React Router 7 renders <form data-discover> and intercepts
			// submissions client-side, matching the action path against its
			// own routes. Rewriting the action to the proxied absolute URL
			// (/auth.openai.com/log-in/password) makes the router match its
			// catch-all SPLAT route instead of the real action route, so it
			// never mints the anti-bot token and the request is rejected
			// upstream. Leave the action untouched and let the runtime shim
			// rewrite the URL when the router issues its fetch.
			preserveFormAction := false
			if tag == "form" {
				for _, a := range attrs {
					if strings.EqualFold(a.Key, "data-discover") {
						preserveFormAction = true
						break
					}
				}
			}

			rewritten := attrs[:0]
			for _, a := range attrs {
				key := strings.ToLower(a.Key)
				switch {
				case key == "integrity":
					// rewritten content would break subresource integrity
					continue
				case preserveFormAction && key == "action":
					// keep React Router form actions as-is so client-side
					// route matching still works
				case key == "href" && tag == "base":
					a.Val = p.rewriteURLIn(a.Val, pageHost)
					sawBase = true
				case key == "srcset" || key == "data-srcset":
					a.Val = p.rewriteSrcset(a.Val, pageHost)
				case key == "style":
					a.Val = p.rewriteCSSIn(a.Val, pageHost)
				case urlAttrs[key]:
					a.Val = p.rewriteURLIn(a.Val, pageHost)
				}
				rewritten = append(rewritten, a)
			}

			if tag == "meta" {
				rewritten = p.rewriteMeta(rewritten, pageHost)
			}
			if tag == "input" || tag == "button" {
				rewritten = p.rewriteFormURLInputs(rewritten)
			}

			if tag == "style" {
				inStyle = true
			}
			if tag == "script" {
				inScript = true
			}
			if tag == "body" {
				flushHead()
			}
			emitTag(tag, rewritten, tt == html.SelfClosingTagToken)
			if tag == "head" {
				if buffering && headOpenEnd == -1 {
					headOpenEnd = head.Len()
				}
			}

		case html.EndTagToken:
			name := endTagName(z.Raw())
			switch name {
			case "style":
				inStyle = false
			case "script":
				inScript = false
			case "head":
				flushHead()
			}
			write(z.Raw())

		case html.TextToken:
			data := z.Text()
			if inStyle {
				data = []byte(p.rewriteCSSIn(string(data), pageHost))
			} else if inScript {
				data = p.rewriteAbsURLs(data)
			}
			write(data)
		}
	}
}

// spaStripScript returns a tiny script that rewrites the current history entry
// by removing the proxy path prefix, so SPA routers match the target's native
// routes. Future navigations and reloads work because unprefixed paths are
// served by the root fallback.
func spaStripScript(prefix string) string {
	js := `!function(){try{var P=__P__;var p=location.pathname;if(P!=="/"&&p.indexOf(P)===0){var n=p.slice(P.length);if(!n)n="/";if(n[0]!=="/")n="/"+n;history.replaceState(history.state,"",n+location.search+location.hash)}}catch(e){}}();`
	return strings.ReplaceAll(js, "__P__", strconv.Quote(prefix))
}

func endTagName(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "</")
	s = strings.TrimSuffix(s, ">")
	return strings.ToLower(strings.TrimSpace(s))
}

func (p *Proxy) rewriteMeta(attrs []html.Attribute, pageHost string) []html.Attribute {
	httpEquiv := ""
	hasContent := false
	for _, a := range attrs {
		switch strings.ToLower(a.Key) {
		case "http-equiv":
			httpEquiv = a.Val
		case "content":
			hasContent = true
		}
	}
	if strings.EqualFold(httpEquiv, "refresh") && hasContent {
		for i := range attrs {
			if strings.EqualFold(attrs[i].Key, "content") {
				attrs[i].Val = p.rewriteMetaRefresh(attrs[i].Val, pageHost)
			}
		}
		return attrs
	}
	// social/canonical tags: rewrite og:url, og:image, twitter:url, etc.
	for _, a := range attrs {
		key := strings.ToLower(a.Key)
		if key != "property" && key != "name" {
			continue
		}
		v := strings.ToLower(a.Val)
		if strings.HasPrefix(v, "og:") || strings.HasPrefix(v, "twitter:") || v == "canonical" {
			for i := range attrs {
				if strings.EqualFold(attrs[i].Key, "content") {
					attrs[i].Val = p.rewriteURLIn(attrs[i].Val, pageHost)
				}
			}
			break
		}
	}
	return attrs
}

// rewriteFormURLInputs rewrites the value of inputs whose name is a
// URL-valued parameter (e.g. redirect_uri) so form-based OAuth flows stay on
// the proxy domain.
func (p *Proxy) rewriteFormURLInputs(attrs []html.Attribute) []html.Attribute {
	name := ""
	for _, a := range attrs {
		if strings.EqualFold(a.Key, "name") {
			name = strings.ToLower(strings.TrimSpace(a.Val))
			break
		}
	}
	if name == "" || (!urlParamsToRewrite[name] && !urlParamsToRewrite[strings.TrimSuffix(name, "[]")]) {
		return attrs
	}
	for i := range attrs {
		if strings.EqualFold(attrs[i].Key, "value") {
			attrs[i].Val = p.rewriteAbsParam(attrs[i].Val)
		}
	}
	return attrs
}

func (p *Proxy) rewriteMetaRefresh(content, pageHost string) string {
	m := metaRefreshRe.FindStringSubmatch(content)
	if m == nil {
		return content
	}
	quote := m[2]
	return m[1] + quote + p.rewriteURLIn(m[3], pageHost) + quote
}

func (p *Proxy) rewriteSrcset(v, pageHost string) string {
	parts := strings.Split(v, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		fields[0] = p.rewriteURLIn(fields[0], pageHost)
		parts[i] = strings.Join(fields, " ")
	}
	return strings.Join(parts, ", ")
}

func (p *Proxy) rewriteCSS(css string) string {
	return p.rewriteCSSIn(css, "")
}

func (p *Proxy) rewriteCSSIn(css, pageHost string) string {
	css = cssURLRe.ReplaceAllStringFunc(css, func(m string) string {
		idx := cssURLRe.FindStringSubmatchIndex(m)
		quote := ""
		u := ""
		switch {
		case idx[2] >= 0:
			quote = "'"
			u = m[idx[2]:idx[3]]
		case idx[4] >= 0:
			quote = `"`
			u = m[idx[4]:idx[5]]
		case idx[6] >= 0:
			u = m[idx[6]:idx[7]]
		}
		return "url(" + quote + p.rewriteURLIn(u, pageHost) + quote + ")"
	})
	css = cssImportRe.ReplaceAllStringFunc(css, func(m string) string {
		mm := cssImportRe.FindStringSubmatch(m)
		return mm[1] + mm[2] + p.rewriteURLIn(mm[3], pageHost) + mm[4]
	})
	return css
}

// rewriteAbsURLs rewrites absolute URLs inside JavaScript or JSON payloads so
// every external host goes through the proxy (catch-all). Bare protocol-
// relative "//host" references are left alone (see absURLRe): rewriting them
// corrupts JS regex literals like /^https?:\/\//, and the runtime shim
// handles any real protocol-relative requests.
func (p *Proxy) rewriteAbsURLs(data []byte) []byte {
	return absURLRe.ReplaceAllFunc(data, func(m []byte) []byte {
		s := string(m)
		rest := s
		scheme := ""
		lower := strings.ToLower(rest)
		switch {
		case strings.HasPrefix(lower, "wss://"):
			scheme = "wss"
			rest = rest[len("wss://"):]
		case strings.HasPrefix(lower, "ws://"):
			scheme = "ws"
			rest = rest[len("ws://"):]
		case strings.HasPrefix(lower, "https://"):
			scheme = "https"
			rest = rest[len("https://"):]
		case strings.HasPrefix(lower, "http://"):
			scheme = "http"
			rest = rest[len("http://"):]
		default:
			return m
		}
		host := rest
		path := ""
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			host = rest[:i]
			path = rest[i:]
		}
		if !p.shouldProxyHost(host) {
			return m
		}
		if scheme == "wss" || scheme == "ws" {
			// WebSocket URLs keep their scheme and move the host into the
			// own domain's host prefix: wss://ws.chatgpt.com/x -> wss://own/x.
			return []byte(scheme + "://" + p.cfg.OwnDomain.Host + "/" + host + path)
		}
		return []byte(p.rewriteURLParams(p.ownOrigin + "/" + host + path))
	})
}
