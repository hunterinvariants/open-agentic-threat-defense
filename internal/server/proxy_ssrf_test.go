package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
)

// H2 regression: a loopback TCP peer (the common same-host reverse-proxy case)
// must NOT grant the gateway proxy access to loopback/internal upstreams.
func TestGatewayProxyBlocksLoopbackPeerByDefault(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/gateway/proxy",
		strings.NewReader(`{"upstream_url":"http://127.0.0.1:1234","tool_call":{"tool_name":"asset_inventory"}}`))
	req.RemoteAddr = "127.0.0.1:1234" // loopback peer must not unlock local targets
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("loopback upstream must be blocked by default even from a loopback peer, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// M9: the SSRF denylist must also cover RFC 6598 CGNAT and a few reserved ranges.
func TestIsBlockedProxyIPExtraRanges(t *testing.T) {
	blocked := []string{
		"100.64.0.1", "100.127.255.254", // RFC 6598
		"0.1.2.3",       // 0.0.0.0/8
		"192.0.0.5",     // 192.0.0.0/24
		"198.18.0.1",    // 198.18.0.0/15
		"127.0.0.1",     // loopback (existing)
		"10.0.0.1",      // RFC1918 (existing)
		"169.254.169.254", // link-local IMDS (existing)
		"::1",           // IPv6 loopback (existing)
	}
	for _, s := range blocked {
		if !isBlockedProxyIP(net.ParseIP(s)) {
			t.Fatalf("%s must be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"}
	for _, s := range allowed {
		if isBlockedProxyIP(net.ParseIP(s)) {
			t.Fatalf("%s must NOT be blocked", s)
		}
	}
}

// M8: userinfo credentials must be stripped before a URL is stored/logged.
func TestRedactURLCredentials(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@internal.example/x?q=1": "https://internal.example/x?q=1",
		"https://token@host/y":                     "https://host/y",
		"https://host/z":                           "https://host/z",
		"http://127.0.0.1:8080/a":                  "http://127.0.0.1:8080/a",
	}
	for in, want := range cases {
		if got := redactURLCredentials(in); got != want {
			t.Fatalf("redactURLCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}
