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

func TestSessionLoginAndAuthenticate(t *testing.T) {
	a := New([]UserConfig{{Name: "alice", TokenHash: HashToken("secret"), Roles: []string{RoleOperator}}}, "")
	info, sessionID, ok := a.Login("alice", "secret")
	if !ok {
		t.Fatal("expected login to succeed")
	}
	if info.Principal.Name != "alice" || info.ExpiresAt.IsZero() {
		t.Fatalf("unexpected session info: %#v", info)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})

	session, ok := a.Session(req)
	if !ok || session.Principal.Name != "alice" {
		t.Fatalf("unexpected session lookup: %#v", session)
	}

	principal, ok := a.Authenticate(req)
	if !ok || principal.Name != "alice" {
		t.Fatalf("unexpected authenticated principal: %#v", principal)
	}

	if !a.Logout(req) {
		t.Fatal("expected logout to validate session")
	}
	if _, ok := a.Session(req); !ok {
		t.Fatal("expected stateless session to remain parseable")
	}
}

func TestRequiredRoles(t *testing.T) {
	if roles := RequiredRoles(http.MethodPost, "/api/responses/approve"); len(roles) != 1 || roles[0] != RoleOperator {
		t.Fatalf("unexpected approve roles: %#v", roles)
	}
	if roles := RequiredRoles(http.MethodGet, "/api/audit"); len(roles) != 2 || roles[0] != RoleAnalyst || roles[1] != RoleOperator {
		t.Fatalf("unexpected audit roles: %#v", roles)
	}
}
