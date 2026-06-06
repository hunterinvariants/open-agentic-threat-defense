package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateUserToken(t *testing.T) {
	a := New([]UserConfig{{Name: "alice", TokenHash: HashToken("secret"), Roles: []string{RoleOperator}}}, "")
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer secret")

	principal, ok := a.Authenticate(req)
	if !ok {
		t.Fatal("expected authentication")
	}
	if principal.Name != "alice" || !principal.HasAny(RoleOperator) {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestRequiredRoles(t *testing.T) {
	if roles := RequiredRoles(http.MethodPost, "/api/responses/approve"); len(roles) != 1 || roles[0] != RoleOperator {
		t.Fatalf("unexpected approve roles: %#v", roles)
	}
}
