package main

import (
	"net"
	"net/http"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestChromeH1SpecWireALPN(t *testing.T) {
	// The wire ClientHello must offer only http/1.1 in ALPN. Regresses the
	// case where the Chrome_131 preset is silently re-applied during the
	// handshake, restoring "h2, http/1.1" and making Cloudflare negotiate
	// HTTP/2 over a connection the proxy then speaks HTTP/1.1 on.
	spec, err := chromeH1Spec()
	if err != nil {
		t.Fatal(err)
	}
	uconn := utls.UClient(&net.TCPConn{}, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	uconn.MarshalClientHello()
	raw := uconn.HandshakeState.Hello.Raw
	protos := alpnOfClientHello(t, raw)
	if len(protos) != 1 || protos[0] != "http/1.1" {
		t.Fatalf("wire ALPN = %v, want [http/1.1]", protos)
	}
}

// alpnOfClientHello parses the ALPN protocol list out of a raw ClientHello
// record (without parsing the TLS record header).
func alpnOfClientHello(t *testing.T, b []byte) []string {
	t.Helper()
	if len(b) < 4 || b[0] != 0x01 {
		t.Fatalf("not a ClientHello handshake message")
	}
	p := 4 // handshake header (1 type + 3 length)
	if p+38 > len(b) {
		t.Fatalf("record too short")
	}
	p += 34 // version + random
	if p+1 > len(b) {
		t.Fatalf("no session id length")
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		t.Fatalf("no cipher suites length")
	}
	csLen := int(b[p])<<8 | int(b[p+1])
	p += 2 + csLen
	if p+1 > len(b) {
		t.Fatalf("no compression methods length")
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		t.Fatalf("no extensions length")
	}
	extLen := int(b[p])<<8 | int(b[p+1])
	p += 2
	end := p + extLen
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		id := int(b[p])<<8 | int(b[p+1])
		l := int(b[p+2])<<8 | int(b[p+3])
		body := b[p+4 : p+4+l]
		if id == 16 { // application_layer_protocol_negotiation
			var protos []string
			if len(body) < 2 {
				t.Fatalf("ALPN body too short")
			}
			listLen := int(body[0])<<8 | int(body[1])
			q := 2
			for q+1 <= 2+listLen {
				n := int(body[q])
				q++
				protos = append(protos, string(body[q:q+n]))
				q += n
			}
			return protos
		}
		p += 4 + l
	}
	t.Fatalf("no ALPN extension in ClientHello")
	return nil
}
func TestIsUpgradeRequest(t *testing.T) {
	cases := []struct {
		name string
		hdr  http.Header
		want bool
	}{
		{"websocket", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, true},
		{"lowercase", http.Header{"connection": {"keep-alive, upgrade"}, "upgrade": {"WebSocket"}}, true},
		{"no-upgrade-header", http.Header{"Connection": {"Upgrade"}}, false},
		{"no-connection", http.Header{"Upgrade": {"websocket"}}, false},
		{"normal", http.Header{"Connection": {"keep-alive"}}, false},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", "http://x/", nil)
		req.Header = c.hdr
		if got := isUpgradeRequest(req); got != c.want {
			t.Errorf("%s: isUpgradeRequest = %v, want %v", c.name, got, c.want)
		}
	}
}
