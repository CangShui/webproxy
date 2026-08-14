package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Config holds the runtime configuration supplied via command line flags.
type Config struct {
	OwnDomain     *url.URL // your public domain, e.g. https://example.com
	Target        *url.URL // the site to reverse proxy, e.g. https://claude.ai
	Listen        string   // listen address, e.g. :8080
	BarePrefixes  []string // extra root paths proxied straight to the target (e.g. /cdn-cgi/)
	ExtraDomains  []string // extra registrable domains to proxy, with subdomains (e.g. openai.com)
	DirectDomains []string // hostnames never proxied; loaded from their real origin (e.g. sentinel.openai.com)
	RootFallback  bool     // proxy unprefixed paths to the target (SPA mode)
	RootSite      bool     // serve the target at the own-domain root ("/"), no path prefix (nginx-style SPA hosting)
	UpstreamProxy *url.URL // optional socks5:// or http:// proxy for upstream fetches
	TLS           bool     // serve HTTPS
	CertFile      string   // TLS certificate file (PEM)
	KeyFile       string   // TLS private key file (PEM)
}

func main() {
	ownDomain := flag.String("own-domain", "http://localhost:8080", "your public domain, e.g. https://example.com")
	target := flag.String("target", "https://claude.ai", "target website to reverse proxy, e.g. https://claude.ai")
	listen := flag.String("listen", ":8080", "listen address, e.g. :8080")
	barePrefix := flag.String("bare-prefix", "/cdn-cgi/", "comma-separated extra root paths proxied straight to the target, e.g. /cdn-cgi/")
	rootFallback := flag.Bool("root-fallback", true, "proxy unprefixed paths to the target (SPA mode; makes client-side routed apps work)")
	rootSite := flag.Bool("root-site", false, "serve the target at the own-domain root \"/\" with no path prefix (nginx-style; use with a dedicated subdomain per target). Client-side-router SPAs like ChatGPT/Claude work best this way.")
	extraDomain := flag.String("extra-domain", "", "optional: extra registrable domains to treat as known hosts (all external hosts are proxied by default anyway), e.g. openai.com")
	directDomain := flag.String("direct-domain", "", "comma-separated hostnames that must never be proxied (loaded straight from their real origin), e.g. hcaptcha.com if the CAPTCHA breaks")
	tlsFlag := flag.Bool("tls", false, "serve HTTPS with a self-signed certificate (auto-generated and reused)")
	certFile := flag.String("cert", "", "TLS certificate file (PEM); requires -key")
	upstreamProxy := flag.String("upstream-proxy", "", "optional upstream proxy for fetching the target (socks5://host:port or http://host:port), useful when the server IP is blocked by the target's bot protection")
	keyFile := flag.String("key", "", "TLS private key file (PEM); requires -cert")
	flag.Parse()

	cfg, err := parseConfig(*ownDomain, *target, *listen, *barePrefix, *rootFallback, *rootSite, *extraDomain, *directDomain, *tlsFlag, *certFile, *keyFile, *upstreamProxy)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	proxy := NewProxy(cfg)

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	base := strings.TrimRight(cfg.OwnDomain.String(), "/")
	fmt.Println("Reverse proxy started")
	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}
	fmt.Printf("  Listen:   %s (%s)\n", cfg.Listen, scheme)
	fmt.Printf("  Own site: %s\n", cfg.OwnDomain.String())
	fmt.Printf("  Target:   %s\n", cfg.Target.String())
	if cfg.RootSite {
		fmt.Printf("  Access:   %s/  (target served at own-domain root, no /%s/ prefix)\n", base, cfg.Target.Host)
	} else {
		fmt.Printf("  Access:   %s/%s/\n", base, cfg.Target.Host)
	}
	fmt.Printf("  SPA mode: root-fallback=%v root-site=%v\n", cfg.RootFallback, cfg.RootSite)
	fmt.Println("  Rewrite: all external links are proxied by default; use -direct-domain to exclude hosts")
	if len(cfg.ExtraDomains) > 0 {
		fmt.Printf("  Extra:    proxied domains: %s\n", strings.Join(cfg.ExtraDomains, ", "))
	}
	if cfg.TLS && cfg.OwnDomain.Scheme != "https" {
		fmt.Println("  Note:     -tls is on but -own-domain is http://; pass -own-domain https://... so rewritten URLs match")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		log.Println("shutting down")
		server.Close()
	}()

	if cfg.TLS {
		cert, key, err := resolveTLSFiles(cfg.CertFile, cfg.KeyFile, cfg.OwnDomain.Hostname())
		if err != nil {
			log.Fatalf("TLS: %v", err)
		}
		if cfg.CertFile == "" && cfg.KeyFile == "" {
			fmt.Println("  TLS:      self-signed certificate generated; browsers will show a warning")
		} else {
			fmt.Printf("  TLS:      using %s / %s\n", cert, key)
		}
		if err := server.ListenAndServeTLS(cert, key); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func parseConfig(ownDomain, target, listen, barePrefix string, rootFallback, rootSite bool, extraDomain, directDomain string, tlsFlag bool, certFile, keyFile string, upstreamProxy string) (Config, error) {
	var cfg Config
	own, err := url.Parse(ownDomain)
	if err != nil {
		return cfg, fmt.Errorf("own-domain: %w", err)
	}
	if own.Scheme != "http" && own.Scheme != "https" {
		return cfg, fmt.Errorf("own-domain must use http:// or https://")
	}
	if own.Host == "" {
		return cfg, fmt.Errorf("own-domain must include a host")
	}
	tgt, err := url.Parse(target)
	if err != nil {
		return cfg, fmt.Errorf("target: %w", err)
	}
	if tgt.Scheme != "http" && tgt.Scheme != "https" {
		return cfg, fmt.Errorf("target must use http:// or https://")
	}
	if tgt.Host == "" {
		return cfg, fmt.Errorf("target must include a host")
	}
	if tgt.Path != "" && tgt.Path != "/" {
		return cfg, fmt.Errorf("target path must be root (/), got %q", tgt.Path)
	}
	if listen == "" {
		return cfg, fmt.Errorf("listen address must not be empty")
	}
	cfg.OwnDomain = own
	cfg.Target = tgt
	cfg.Listen = listen
	cfg.RootFallback = rootFallback
	cfg.RootFallback = cfg.RootFallback || rootSite // root-site implies unprefixed paths go to the target
	cfg.RootSite = rootSite
	for _, d := range strings.Split(extraDomain, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "/: ") || strings.Contains(d, "://") {
			return cfg, fmt.Errorf("extra-domain %q must be a bare hostname like openai.com", d)
		}
		cfg.ExtraDomains = append(cfg.ExtraDomains, d)
	}
	for _, d := range strings.Split(directDomain, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "/: ") || strings.Contains(d, "://") {
			return cfg, fmt.Errorf("direct-domain %q must be a bare hostname like sentinel.openai.com", d)
		}
		cfg.DirectDomains = append(cfg.DirectDomains, d)
	}
	if up := strings.TrimSpace(upstreamProxy); up != "" {
		u, err := url.Parse(up)
		if err != nil {
			return cfg, fmt.Errorf("upstream-proxy: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h", "http", "https":
		default:
			return cfg, fmt.Errorf("upstream-proxy must use socks5:// or http://, got %q", u.Scheme)
		}
		if u.Host == "" {
			return cfg, fmt.Errorf("upstream-proxy must include a host")
		}
		cfg.UpstreamProxy = u
	}
	cfg.TLS = tlsFlag || certFile != "" || keyFile != ""
	if (certFile == "") != (keyFile == "") {
		return cfg, fmt.Errorf("-cert and -key must be provided together")
	}
	cfg.CertFile = certFile
	cfg.KeyFile = keyFile
	for _, bp := range strings.Split(barePrefix, ",") {
		bp = strings.TrimSpace(bp)
		if bp == "" {
			continue
		}
		if !strings.HasPrefix(bp, "/") {
			return cfg, fmt.Errorf("bare-prefix %q must start with /", bp)
		}
		if !strings.HasSuffix(bp, "/") {
			bp += "/"
		}
		cfg.BarePrefixes = append(cfg.BarePrefixes, bp)
	}
	return cfg, nil
}
