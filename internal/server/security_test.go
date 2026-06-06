package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
)

func TestValidateListenAddressRequiresAuthenticationOrInsecure(t *testing.T) {
	if err := ValidateListenAddress(":8080", false, false); err == nil {
		t.Fatal("expected non-loopback open listener to be rejected")
	}
	if err := ValidateListenAddress("127.0.0.1:8080", false, false); err != nil {
		t.Fatalf("expected loopback listener to be allowed: %v", err)
	}
	if err := ValidateListenAddress("localhost:8080", false, false); err != nil {
		t.Fatalf("expected localhost listener to be allowed: %v", err)
	}
	if err := ValidateListenAddress(":8080", false, true); err != nil {
		t.Fatalf("expected insecure override to allow listener: %v", err)
	}
}

func TestSecurityHeadersIncludeCSP(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("unexpected CSP header: %q", csp)
	}
}

func TestTrustedProxyUsesForwardedFor(t *testing.T) {
	app, err := NewWithOptions(Options{
		TrustedProxies: []string{"10.0.0.0/8"},
		Users:          []auth.UserConfig{{Name: "alice", TokenHash: auth.HashToken("secret"), Roles: []string{auth.RoleOperator}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.1.2.3")
	if got := app.sourceIP(req); got != "203.0.113.9" {
		t.Fatalf("expected forwarded IP, got %q", got)
	}
}

func TestUntrustedProxyIgnoresForwardedFor(t *testing.T) {
	app, err := NewWithOptions(Options{
		TrustedProxies: []string{"10.0.0.0/8"},
		Users:          []auth.UserConfig{{Name: "alice", TokenHash: auth.HashToken("secret"), Roles: []string{auth.RoleOperator}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.1.2.3")
	if got := app.sourceIP(req); got != "192.0.2.1" {
		t.Fatalf("expected remote address, got %q", got)
	}
}

func TestLoginRateLimitReturns429(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{Name: "alice", TokenHash: auth.HashToken("secret"), Roles: []string{auth.RoleOperator}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"alice","token":"wrong"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected first failure 401, got %d", rec.Code)
	}

	// The next request should be rate-limited for the same source IP.
	req = httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"alice","token":"wrong"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second failure 429, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestServerReadinessRetainsUptime(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if time.Since(app.startedAt) < 0 {
		t.Fatal("startedAt must be in the past")
	}
}
