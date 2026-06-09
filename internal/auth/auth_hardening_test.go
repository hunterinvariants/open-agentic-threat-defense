package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginBruteForceLockout(t *testing.T) {
	a := New(nil, "")

	first := a.RecordLoginAttempt("ip-1", false)
	if first < time.Second {
		t.Fatalf("first failure should block for at least ~1s, got %s", first)
	}
	second := a.RecordLoginAttempt("ip-1", false)
	if second <= first {
		t.Fatalf("backoff should grow with repeated failures: first=%s second=%s", first, second)
	}
	if a.LoginRetryAfter("ip-1") <= 0 {
		t.Fatal("the key should be blocked after repeated failures")
	}

	if cleared := a.RecordLoginAttempt("ip-1", true); cleared != 0 {
		t.Fatalf("a successful login should clear the lockout, got %s", cleared)
	}
	if a.LoginRetryAfter("ip-1") != 0 {
		t.Fatal("retry-after should reset after a successful login")
	}
}

func TestAuthenticateRejectsBadToken(t *testing.T) {
	a := New([]UserConfig{{Name: "alice", TokenHash: HashToken("good-token"), Roles: []string{RoleOperator}}}, "")

	missing := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	if _, ok := a.Authenticate(missing); ok {
		t.Fatal("a request without a token must not authenticate")
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	bad.Header.Set("Authorization", "Bearer wrong-token")
	if _, ok := a.Authenticate(bad); ok {
		t.Fatal("a wrong token must not authenticate")
	}

	good := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	good.Header.Set("Authorization", "Bearer good-token")
	principal, ok := a.Authenticate(good)
	if !ok || principal.Name != "alice" || !principal.HasAny(RoleOperator) {
		t.Fatalf("the correct token should authenticate as alice/operator, got %+v ok=%v", principal, ok)
	}
}

func TestPrincipalHasAny(t *testing.T) {
	analyst := Principal{Roles: []string{RoleAnalyst, RoleViewer}}
	if !analyst.HasAny(RoleOperator, RoleAnalyst) {
		t.Fatal("analyst should match a required set that includes analyst")
	}
	if analyst.HasAny(RoleAdmin) {
		t.Fatal("a non-admin should not satisfy an admin-only requirement")
	}
	if analyst.HasAny() {
		t.Fatal("an empty requirement should not match")
	}

	admin := Principal{Roles: []string{RoleAdmin}}
	if !admin.HasAny(RoleViewer) {
		t.Fatal("admin should satisfy any required role")
	}
}
