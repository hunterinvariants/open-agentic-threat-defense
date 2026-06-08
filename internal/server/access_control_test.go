package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
)

// M10: the SSRF-capable proxy endpoints must not be reachable when authentication
// is not configured (open mode).
func TestProxyEndpointsDenyInOpenMode(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	for _, path := range []string{"/api/gateway/proxy", "/api/mcp/proxy"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s in open mode must return 503, got %d", path, rec.Code)
		}
	}
}

// M7: per-tenant backend administration is scoped, not a global admin wildcard.
func TestCanAdministerTenant(t *testing.T) {
	platform := auth.Principal{Name: "root", Tenant: "default", Roles: []string{auth.RoleAdmin}}
	tenantAdmin := auth.Principal{Name: "alice", Tenant: "acme", Roles: []string{auth.RoleAdmin}}
	rec := tenantBackendConfig{Admins: []string{"bob"}}

	if !canAdministerTenant(platform, "acme", rec, true) {
		t.Fatal("platform admin (default tenant) should manage any tenant")
	}
	if !canAdministerTenant(tenantAdmin, "acme", rec, true) {
		t.Fatal("a tenant admin should manage their own tenant")
	}
	if canAdministerTenant(tenantAdmin, "other", rec, true) {
		t.Fatal("a tenant admin must not manage an unrelated tenant")
	}
	bob := auth.Principal{Name: "bob", Tenant: "x", Roles: []string{auth.RoleAdmin}}
	if !canAdministerTenant(bob, "acme", rec, true) {
		t.Fatal("an admin listed in the tenant's Admins should manage it")
	}
	viewer := auth.Principal{Name: "v", Tenant: "default", Roles: []string{auth.RoleViewer}}
	if canAdministerTenant(viewer, "acme", rec, true) {
		t.Fatal("a non-admin must be denied")
	}
}
