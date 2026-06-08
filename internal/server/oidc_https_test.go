package server

import (
	"strings"
	"testing"
)

func TestRequireSecureOIDCEndpoint(t *testing.T) {
	allowed := []string{
		"https://idp.example.com/",
		"https://login.microsoftonline.com/tenant/v2.0",
		"http://localhost:8080/realms/x",
		"http://127.0.0.1:9000/",
		"http://[::1]:9000/",
	}
	for _, u := range allowed {
		if err := requireSecureOIDCEndpoint("issuer", u); err != nil {
			t.Fatalf("expected %q to be allowed, got %v", u, err)
		}
	}
	rejected := []string{
		"http://idp.example.com/",
		"http://10.0.0.5/",
		"ftp://idp.example.com/",
		"http://attacker.example/.well-known",
	}
	for _, u := range rejected {
		if err := requireSecureOIDCEndpoint("issuer", u); err == nil {
			t.Fatalf("expected %q to be rejected", u)
		}
	}
}

// M6: a multi-valued audience requires an azp check.
func TestAudienceIsMultiValued(t *testing.T) {
	if !audienceIsMultiValued([]any{"client-a", "client-b"}) {
		t.Fatal("a 2-element aud array must be multi-valued")
	}
	if !audienceIsMultiValued([]string{"a", "b"}) {
		t.Fatal("a 2-element string aud array must be multi-valued")
	}
	if audienceIsMultiValued([]any{"client-a"}) {
		t.Fatal("a single-element aud array is not multi-valued")
	}
	if audienceIsMultiValued("client-a") {
		t.Fatal("a string aud is not multi-valued")
	}
	if audienceIsMultiValued(nil) {
		t.Fatal("a nil aud is not multi-valued")
	}
}

func TestNewOIDCProviderRejectsPlainHTTPIssuer(t *testing.T) {
	// A plain-http issuer must be rejected before any network discovery fetch.
	_, err := newOIDCProvider(
		"http://idp.example.com", "client-id", "secret", "https://app.example/callback",
		nil, "tenant", "roles", "email", []byte("0123456789abcdef0123456789abcdef"),
	)
	if err == nil {
		t.Fatal("expected newOIDCProvider to reject a plain-http issuer")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected an https-related error, got %v", err)
	}
}
