package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// chatgptRootProxy returns a root-site proxy whose target is chatgpt.com.
func chatgptRootProxy() *Proxy {
	own, _ := url.Parse("http://localhost:8080")
	tgt, _ := url.Parse("https://chatgpt.com")
	return NewProxy(Config{OwnDomain: own, Target: tgt, RootSite: true, RootFallback: true})
}

func TestRootSiteAbsoluteTargetToRoot(t *testing.T) {
	p := chatgptRootProxy()
	if got := p.rewriteURLIn("https://chatgpt.com/c/xyz", ""); got != "http://localhost:8080/c/xyz" {
		t.Fatalf("target abs = %q", got)
	}
	if got := p.rewriteURLIn("https://api.chatgpt.com/v1/x", ""); got != "http://localhost:8080/api.chatgpt.com/v1/x" {
		t.Fatalf("target subdomain = %q (must keep prefix)", got)
	}
	if got := p.rewriteURLIn("/login", ""); got != "/login" {
		t.Fatalf("root-relative = %q", got)
	}
}

func TestRootSiteOtherHostPrefixed(t *testing.T) {
	p := chatgptRootProxy()
	if got := p.rewriteURLIn("https://auth.openai.com/log-in", ""); got != "http://localhost:8080/auth.openai.com/log-in" {
		t.Fatalf("other host = %q", got)
	}
}

func TestRootSiteHTMLRewrite(t *testing.T) {
	p := chatgptRootProxy()
	var raw = "<html><head><title>x</title><script>window.__reactRouterContext = {\"basename\":\"/\"};</script></head><body><a href=\"/images\">i</a><a href=\"https://chatgpt.com/c/1\">c</a><a href=\"https://auth.openai.com/log-in\">a</a></body></html>"
	out := string(p.rewriteHTML([]byte(raw), "http://localhost:8080/images"))
	if !strings.Contains(out, "href=\"/images\"") {
		t.Errorf("images unprefixed:\n%s", out)
	}
	if !strings.Contains(out, "href=\"http://localhost:8080/c/1\"") {
		t.Errorf("target abs to root:\n%s", out)
	}
	if !strings.Contains(out, "http://localhost:8080/auth.openai.com/log-in") {
		t.Errorf("auth prefixed:\n%s", out)
	}
	if !strings.Contains(out, "\"basename\":\"/\"") {
		t.Errorf("basename / kept:\n%s", out)
	}
}

func TestRootSiteServesAtRoot(t *testing.T) {
	tp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("X-Upstream-Host", r.Host)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte("<html><body><a href=\"/login\">login</a><img src=\"/cdn/a.png\"></body></html>"))
			return
		}
		w.Write([]byte("route:" + r.URL.Path))
	}))
	defer tp.Close()
	tgtURL, _ := url.Parse(tp.URL)
	own, _ := url.Parse("http://localhost:8080")
	px := NewProxy(Config{OwnDomain: own, Target: tgtURL, RootSite: true, RootFallback: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { px.ServeHTTP(w, r) }))
	defer srv.Close()
	// GET / serves the target root directly (no 302 redirect, no /host/ prefix)
	status, _, body := get(t, srv.URL+"/")
	if status != http.StatusOK {
		t.Fatalf("GET / status = %d", status)
	}
	if !strings.Contains(body, "href=\"/login\"") {
		t.Errorf("GET /: relative href not unprefixed:\n%s", body)
	}
	if !strings.Contains(body, "src=\"/cdn/a.png\"") {
		t.Errorf("GET /: resource not unprefixed:\n%s", body)
	}
	// unprefixed path routes to the target
	status2, _, body2 := get(t, srv.URL+"/login")
	if status2 != http.StatusOK {
		t.Fatalf("GET /login status = %d", status2)
	}
	if strings.TrimSpace(body2) != "route:/login" {
		t.Errorf("GET /login body = %q", body2)
	}
}

func TestRootSitePageHostEmpty(t *testing.T) {
	p := chatgptRootProxy()
	if ph := p.pageHostOf("http://localhost:8080/login"); ph != "" {
		t.Fatalf("pageHostOf(login) = %q", ph)
	}
	if ph := p.pageHostOf("http://localhost:8080/auth.openai.com/log-in"); ph != "auth.openai.com" {
		t.Fatalf("pageHostOf(auth) = %q", ph)
	}
	if ph := p.pageHostOf("http://localhost:8080/chatgpt.com/images"); ph != "" {
		t.Fatalf("pageHostOf(/chatgpt.com/images) = %q, want empty in root-site", ph)
	}
}
func TestRootSiteDataRouteGoesToTarget(t *testing.T) {
	tp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request reaches this target; record the upstream path so we can
		// assert the proxy did NOT try to connect to a host named "projects.data".
		w.Header().Set("X-Upstream-Path", r.URL.Path)
		w.Write([]byte("target:" + r.URL.Path))
	}))
	defer tp.Close()
	tgtURL, _ := url.Parse(tp.URL)
	own, _ := url.Parse("http://localhost:8080")
	px := NewProxy(Config{OwnDomain: own, Target: tgtURL, RootSite: true, RootFallback: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { px.ServeHTTP(w, r) }))
	defer srv.Close()

	// /projects.data/... must be treated as the target's path, not routed to a
	// host named "projects.data" (which would fail with a DNS/connection error).
	status, h, body := get(t, srv.URL+"/projects.data/?_routes=routes%2Fx")
	if status != http.StatusOK {
		t.Fatalf("GET /projects.data status = %d, want 200 (body:%s)", status, body)
	}
	if got := h.Get("X-Upstream-Path"); !strings.HasPrefix(got, "/projects.data") {
		t.Fatalf("upstream path = %q, want /projects.data... (reached target, not host 'projects.data')", got)
	}
	if !strings.Contains(body, "target:") {
		t.Fatalf("body should come from the target, got %q", body)
	}
}

func TestRootSiteOtherHostStillRoutesAsPrefix(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Is-Auth", "1")
		w.Write([]byte("auth-ok"))
	}))
	defer auth.Close()
	authURL, _ := url.Parse(auth.URL)

	// Fake an "extra domain"-like second upstream by using the auth server's host.
	tgt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "tgt", http.StatusTeapot) }))
	defer tgt.Close()
	tgtURL, _ := url.Parse(tgt.URL)

	own, _ := url.Parse("http://localhost:8080")
	px := NewProxy(Config{OwnDomain: own, Target: tgtURL, RootSite: true, RootFallback: true, ExtraDomains: []string{authURL.Host}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { px.ServeHTTP(w, r) }))
	defer srv.Close()

	// /authhost/... must route to the extra-domain upstream (prefixed form).
	status, h, _ := get(t, srv.URL+"/"+authURL.Host+"/x")
	if status != http.StatusOK {
		t.Fatalf("prefixed extra host status = %d, want 200", status)
	}
	if h.Get("X-Is-Auth") != "1" {
		t.Fatalf("prefixed extra host did not reach its upstream")
	}
}
