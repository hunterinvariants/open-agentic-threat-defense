package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// M1: logging out must revoke the session server-side so the signed cookie can
// no longer be replayed.
func TestSessionRevocationOnLogout(t *testing.T) {
	t.Setenv("OATD_SESSION_SECRET", "test-session-secret-0123456789abcdef")
	a := New(nil, "")
	if len(a.sessionKey) == 0 {
		t.Fatal("expected a session key from OATD_SESSION_SECRET")
	}

	_, token, ok := a.MintSession(Principal{Name: "alice", Tenant: "default", Roles: []string{RoleViewer}})
	if !ok {
		t.Fatal("mint should succeed")
	}
	withCookie := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		return r
	}

	if _, ok := a.Session(withCookie()); !ok {
		t.Fatal("session should be valid before logout")
	}
	if !a.Logout(withCookie()) {
		t.Fatal("logout should succeed")
	}
	if _, ok := a.Session(withCookie()); ok {
		t.Fatal("session must be rejected after logout (revoked server-side)")
	}

	// A freshly minted session for the same principal is unaffected by the
	// earlier revocation (distinct jti).
	if _, token2, ok := a.MintSession(Principal{Name: "alice", Tenant: "default", Roles: []string{RoleViewer}}); !ok || token2 == token {
		t.Fatal("a new session should mint with a distinct token")
	}
}
