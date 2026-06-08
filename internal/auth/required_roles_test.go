package auth

import (
	"net/http"
	"testing"
)

// I1: admin-only surfaces must resolve to the admin role for every method
// (including GET) from the central RequiredRoles table.
func TestRequiredRolesAdminPaths(t *testing.T) {
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/tenants"},
		{http.MethodPost, "/api/tenants"},
		{http.MethodGet, "/api/tenants/acme"},
		{http.MethodPut, "/api/tenants/acme"},
		{http.MethodDelete, "/api/tenants/acme"},
		{http.MethodGet, "/api/policy/tenants"},
		{http.MethodPost, "/api/policy/tenants"},
		{http.MethodPost, "/api/policy/reload"},
	}
	for _, c := range cases {
		got := RequiredRoles(c.method, c.path)
		if len(got) != 1 || got[0] != RoleAdmin {
			t.Fatalf("%s %s: expected [admin], got %v", c.method, c.path, got)
		}
	}
}
