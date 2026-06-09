package server

import (
	"testing"

	"github.com/crewjam/saml/samlsp"
)

func TestSAMLHelpers(t *testing.T) {
	if firstNonEmpty("", "  ", "x", "y") != "x" {
		t.Fatal("firstNonEmpty should return the first non-empty trimmed value")
	}
	if firstNonEmpty("", "  ") != "" {
		t.Fatal("firstNonEmpty of all-empty should be empty")
	}
	got := splitAttributeValues("analyst, viewer; operator")
	if len(got) != 3 || got[0] != "analyst" || got[2] != "operator" {
		t.Fatalf("splitAttributeValues mismatch: %v", got)
	}
	if splitAttributeValues("") != nil {
		t.Fatal("empty attribute should split to nil")
	}
}

func TestSAMLPrincipalFromAttributes(t *testing.T) {
	provider := &samlProvider{nameAttribute: "email", roleAttribute: "roles", tenantAttribute: "org"}

	attrs := samlsp.Attributes{"email": {"a@b.com"}, "roles": {"analyst viewer"}, "org": {"acme"}}
	principal, err := provider.principalFromAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Name != "a@b.com" || principal.Tenant != "acme" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if len(principal.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %v", principal.Roles)
	}

	if _, err := provider.principalFromAttributes(samlsp.Attributes{}); err == nil {
		t.Fatal("empty attributes should error")
	}
	if _, err := provider.principalFromAttributes(samlsp.Attributes{"roles": {"viewer"}}); err == nil {
		t.Fatal("missing name should error")
	}
}
