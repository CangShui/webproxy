# webproxy

A small Go reverse proxy with URL rewriting. It serves a target website under
path prefixes on your own domain and rewrites every external absolute URL so
the whole site (including its subdomains and third-party resources) is loaded
through the proxy.

Example: reverse proxy `https://claude.ai` from `https://example.com`

| Original resource | Proxied URL |
| --- | --- |
| `https://claude.ai/` | `https://example.com/claude.ai/` |
| `https://claude.ai/style.css` | `https://example.com/claude.ai/style.css` |
| `https://api.claude.ai/v1/test.js` | `https://example.com/api.claude.ai/v1/test.js` |

URLs inside HTML, CSS, JavaScript and JSON responses are rewritten
automatically. Rewriting is catch-all by default: any external host becomes a
path prefix on your domain, so nothing leaks to a real origin unless you
explicitly exclude it. A `<base>` tag is injected into HTML pages so that
root-relative URLs also go through the proxy.

WebSocket URLs (`ws://` / `wss://`) are rewritten the same way, e.g.
`wss://ws.chatgpt.com/...` becomes `wss://example.com/ws.chatgpt.com/...`, and
upgrade requests are tunneled over HTTP/1.1 upstream (HTTP/2 cannot carry
protocol upgrades). The upstream TLS dial uses a Chrome fingerprint but only
offers `http/1.1` in ALPN, so CDNs like Cloudflare negotiate HTTP/1.1 instead
of answering with HTTP/2 frames.

## Build

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o dist/webproxy-linux-amd64 .

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o dist/webproxy-windows-amd64.exe .
```

## Docker

A container image is built automatically on every GitHub release and pushed to
the repository's container registry (`ghcr.io/CangShui/webproxy`).

```bash
# pull the latest image
docker pull ghcr.io/cangshui/webproxy:latest

# run (replace the flags with your own domain / target)
docker run -d --name webproxy -p 443:443 -p 80:80 \
  ghcr.io/cangshui/webproxy \
  -tls -own-domain https://example.com -target https://claude.ai -listen :443 \
  -direct-domain assets-proxy.anthropic.com
```

- The container runs as a non-root user; the working directory `/app` is
  writable so `-tls` can generate and reuse the self-signed certificate there.
- Override the startup flags after the image name (they are appended to the
  binary's `ENTRYPOINT`), or mount your own certificate with `-cert`/`-key`.
- Build locally with `docker build -t webproxy .`.

## Usage

```bash
webproxy -own-domain https://example.com -target https://claude.ai -listen :8080
```

- `-own-domain` — your public domain (used when rewriting URLs), e.g. `https://example.com`
- `-target` — the site to reverse proxy, e.g. `https://claude.ai`
- `-listen` — local listen address, e.g. `:8080`
- `-bare-prefix` — comma-separated extra root paths proxied straight to the
  target host, default `/cdn-cgi/` (used by Cloudflare challenge pages)
- `-extra-domain` — optional, kept for compatibility. All external hosts are
  proxied by default (catch-all), so this flag is no longer needed. If passed,
  the listed registrable domains (with subdomains) are treated as known hosts.
- `-direct-domain` — comma-separated hostnames that must never be proxied and
  are always loaded straight from their real origin. Use it only for hosts
  that genuinely must stay direct (their scripts do origin checks, or their
  CDN rejects server-side fetches). `hcaptcha.com` is already excluded by
  default because proxying it breaks CAPTCHAs. Do NOT put
  `sentinel.openai.com` here: the Sentinel bot-protection frame is synthesized
  and proxied on purpose, so its `/backend-api/sentinel/req` calls stay on
  your own domain instead of leaking to the real host.
- `-root-fallback` — proxy unprefixed paths to the target (SPA mode, default
  `true`). Needed for client-side routed apps like claude.ai that read
  `location.pathname` and make root-relative API calls (`/edge-api/...`).
- `-tls` — serve HTTPS with an auto-generated self-signed certificate (saved as
  `webproxy-cert.pem` / `webproxy-key.pem` next to the binary and reused).
- `-cert` / `-key` — use your own PEM certificate/key instead of the
  self-signed one (must be provided together; implies `-tls`).

Then open `https://example.com/claude.ai/`.

For local testing (plain HTTP):

```bash
webproxy -own-domain http://localhost:8080 -target https://claude.ai -listen :8080
# open http://localhost:8080/claude.ai/
```

Examples:

```bash
# Claude (recommended)
webproxy -tls -own-domain https://example.com -target https://claude.ai -listen :443 \
  -direct-domain assets-proxy.anthropic.com

# ChatGPT (its login spans auth.openai.com; catch-all covers it)
webproxy -tls -own-domain https://example.com -target https://chatgpt.com -listen :443
# login links (auth.openai.com/...) are proxied as https://example.com/auth.openai.com/...
# the Sentinel anti-bot frame and its /backend-api/sentinel/req calls are
# served through the proxy too, so no traffic leaks to sentinel.openai.com.
```

For local HTTPS testing with a self-signed certificate:

```bash
webproxy -tls -own-domain https://localhost:8443 -target https://claude.ai -listen :8443
# open https://localhost:8443/claude.ai/ and accept the certificate warning
```

## Behavior notes

- Path prefix is derived from the host being proxied. The target, its
  subdomains, sibling subdomains of the registrable domain, and any other
  external host are all proxied: `/claude.ai/...`, `/api.claude.ai/...`,
  `/assets-proxy.anthropic.com/...`. A first path segment that looks like a
  hostname routes to that host (file-like segments such as `robots.txt` or
  `app.js` still fall back to the target host).
- Redirects keep query strings, and cookies are re-scoped to the own domain (to
  the root path in SPA mode), so Cloudflare challenge flows (which bounce
  through `/?__cf_chl_rt_tk=...` and `/cdn-cgi/...`) survive the proxy.
- SPA mode: a small script is injected into target pages that strips the path
  prefix from the URL in the browser, so client-side routers match the target's
  native routes. The address bar shows unprefixed paths after the first
  navigation, and unprefixed paths are proxied by the root fallback, so reloads
  and the app's root-relative API calls keep working.
- A runtime shim is injected into every page. It rewrites URLs that sites build
  dynamically in JavaScript: anchor `href` assignments and clicks, `window.open`,
  `fetch`, `XMLHttpRequest`, form submissions (including hidden inputs named
  `redirect_uri`, `next`, `callback`, etc.), and `history.pushState` /
  `replaceState`. A client-side history navigation that crosses proxied hosts
  (e.g. an auth page pushing the target's callback URL) is converted into a
  real full-page navigation, mirroring the cross-origin jump the site would
  perform natively.
- OAuth-style flows: URL parameters whose values are URLs (`redirect_uri`,
  `return_to`, `callback`, ...) are rewritten so the browser stays on the proxy
  domain, and are restored to their original upstream values before the request
  is forwarded, so authorization servers still validate the callback URL they
  were configured with. The authorization server's redirect back to the
  callback is rewritten to the proxy domain again, keeping the whole login flow
  on your domain.
- Responses are rewritten based on `Content-Type`: HTML (attributes, styles,
  `<base>`, meta refresh, srcset), CSS (`url()` and `@import`), and
  JS/JSON (absolute URLs to any external host). Bare protocol-relative
  `//host` references are left alone inside JS/JSON because `//` is also
  comment and regex-literal syntax there (rewriting it corrupts code such as
  `/^https?:\/\//`); the runtime shim handles real protocol-relative requests.
- `Link` response headers (preload/preconnect hints) are rewritten like any
  other URL so the browser does not fetch unrewritten hints directly.
- `Content-Security-Policy`, HSTS and `X-Frame-Options` headers are stripped.
- Cookies are re-scoped to the own domain and the proxied path prefix.
- `integrity` (SRI) attributes are removed because payloads are rewritten.
- Root-relative URLs (e.g. a form `action="/log-in/password"`) are rewritten
  using the current page's host prefix, so a form on
  `https://example.com/auth.openai.com/log-in/password` still posts to the
  `auth.openai.com` host (not the target host). Redirect `Location` headers are
  prefixed the same way; relative locations are left for the browser to resolve
  against the already-proxied request URL.
- The `Origin` and `Referer` request headers are rewritten to the real target
  origins (derived from the proxied page), and `Access-Control-Allow-Origin`
  is reflected back to the own domain, so the target's CORS/CSRF checks and
  credentialed API calls keep working through the proxy.

## Troubleshooting

- Claude's login page shows "This page ran into a problem" (a
  `Cannot set properties of undefined (setting 'flexShrink')` error in its
  Frames SDK): Anthropic's asset CDN checks the origin its scripts are loaded
  from. Keep it direct with `-direct-domain assets-proxy.anthropic.com`.
- Password login returns HTTP 500 even on a "clean" IP: ChatGPT's
  `OpenAI-Sentinel-Token` proof is bound to the origin the sentinel SDK was
  loaded from. If `sentinel.openai.com` is proxied, the SDK sees the proxied
  URL and the server rejects the proof. Test in a real browser; do not add
  `sentinel.openai.com` to `-direct-domain`.
- Headless/automated browsers (Playwright, Selenium, puppeteer) often cannot
  pass Cloudflare/OpenAI bot protection (`sec-ch-ua` exposes automation).
  This is upstream behavior, not a proxy bug. Use a normal browser.
