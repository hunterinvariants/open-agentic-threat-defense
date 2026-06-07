package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTenantPolicyAPIScopesGatewayDecisions(t *testing.T) {
	// APIToken => legacy admin principal whose tenant is "default".
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	admin := func(method, path, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		r.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, r)
		return rec
	}

	execCode := func() int {
		return admin(http.MethodPost, "/api/gateway/execute", `{"tool_name":"asset_inventory","asset_id":"h1"}`).Code
	}

	// Baseline: asset_inventory is globally approved, so it is not denied.
	if code := execCode(); code == http.StatusForbidden {
		t.Fatalf("baseline asset_inventory must not be blocked, got %d", code)
	}

	// Admin installs an org-scoped overlay for "default" that excludes asset_inventory.
	if rec := admin(http.MethodPut, "/api/policy/tenants", `{"tenant_id":"default","approved_tools":["deploy"]}`); rec.Code != http.StatusOK {
		t.Fatalf("set tenant policy: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := admin(http.MethodGet, "/api/policy/tenants", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"default"`) || !strings.Contains(rec.Body.String(), "deploy") {
		t.Fatalf("list tenant policies: got %d (%s)", rec.Code, rec.Body.String())
	}

	// The same call is now denied because the overlay does not approve asset_inventory.
	if code := execCode(); code != http.StatusForbidden {
		t.Fatalf("overlay must deny asset_inventory, got %d", code)
	}

	// Remove the overlay; the call falls back to the global allow.
	if rec := admin(http.MethodDelete, "/api/policy/tenants?tenant_id=default", ""); rec.Code != http.StatusOK {
		t.Fatalf("delete tenant policy: expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if code := execCode(); code == http.StatusForbidden {
		t.Fatalf("after removal asset_inventory must not be blocked, got %d", code)
	}
}

func TestTenantPolicyAPIRequiresAuth(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	// No bearer token -> rejected before reaching the handler.
	req := httptest.NewRequest(http.MethodPut, "/api/policy/tenants", strings.NewReader(`{"tenant_id":"default"}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated tenant policy write must be 401, got %d", rec.Code)
	}
}
