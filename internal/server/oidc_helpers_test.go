package server

import (
	"testing"
	"time"
)

func TestSanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/dashboard":           "/dashboard",
		"/foo?x=1&y=2":         "/foo?x=1&y=2",
		"":                     "/",
		"//evil.example":       "/", // protocol-relative -> open redirect
		"https://evil.example": "/", // absolute external
		"javascript:alert(1)":  "/", // not a path
	}
	for in, want := range cases {
		if got := sanitizeReturnTo(in); got != want {
			t.Fatalf("sanitizeReturnTo(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOIDCStateSignVerify(t *testing.T) {
	key := []byte("oidc-state-key")
	payload := oidcStatePayload{State: "s", Nonce: "n", ReturnTo: "/back", ExpiresAt: time.Now().Add(time.Minute).UTC()}

	token, err := signOIDCState(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := verifyOIDCState(key, token)
	if !ok || got.State != "s" || got.Nonce != "n" || got.ReturnTo != "/back" {
		t.Fatalf("round-trip failed: ok=%v got=%+v", ok, got)
	}

	if _, ok := verifyOIDCState(key, token+"x"); ok {
		t.Fatal("a tampered state must not verify (HMAC integrity)")
	}
	if _, ok := verifyOIDCState([]byte("other-key"), token); ok {
		t.Fatal("a state signed with another key must not verify")
	}
	if _, ok := verifyOIDCState(key, "garbage"); ok {
		t.Fatal("a malformed state must not verify")
	}
}

func TestOIDCClaimHelpers(t *testing.T) {
	if defaultOIDCClaim(" x ", "fb") != "x" {
		t.Fatal("a non-empty trimmed value should be used")
	}
	if defaultOIDCClaim("   ", "fb") != "fb" {
		t.Fatal("an empty value should fall back")
	}

	claims := map[string]any{
		"email":  "  a@b.com ",
		"roles":  "analyst, viewer",
		"groups": []any{"x", "y"},
	}
	if claimString(claims, "email") != "a@b.com" {
		t.Fatalf("claimString should trim, got %q", claimString(claims, "email"))
	}
	if claimString(claims, "missing") != "" {
		t.Fatal("a missing claim should be empty")
	}
	if roles := claimStrings(claims, "roles"); len(roles) != 2 || roles[0] != "analyst" || roles[1] != "viewer" {
		t.Fatalf("claimStrings CSV parse: %v", roles)
	}
	if groups := claimStrings(claims, "groups"); len(groups) != 2 {
		t.Fatalf("claimStrings []any: %v", groups)
	}
	if claimStrings(claims, "missing") != nil {
		t.Fatal("a missing claim list should be nil")
	}
}
