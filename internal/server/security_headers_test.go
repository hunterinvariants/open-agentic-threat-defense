package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Frontend XSS backstop: every response carries a strict CSP (no inline scripts)
// plus the standard hardening headers.
func TestSecurityHeadersPresent(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"script-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "frame-src 'none'", "form-action 'self'", "base-uri 'self'"} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("CSP missing %q: %s", directive, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Fatal("script-src must not allow unsafe-inline")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options: nosniff")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options: DENY")
	}
}
