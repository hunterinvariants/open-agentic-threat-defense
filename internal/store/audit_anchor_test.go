package store

import "testing"

// M3: the audit-anchor key must be domain-separated from the session secret, not
// reused raw, so leaking the session secret does not also yield the audit key.
func TestAuditChainAnchorKeyDomainSeparation(t *testing.T) {
	t.Setenv("OATD_AUDIT_HMAC_SECRET", "")
	t.Setenv("OATD_SESSION_SECRET", "shared-secret")
	key := auditChainAnchorKey()
	if len(key) == 0 {
		t.Fatal("expected a derived audit key from the session secret")
	}
	if string(key) == "shared-secret" {
		t.Fatal("audit key must not be the raw session secret")
	}

	// An explicit dedicated secret is used as-is.
	t.Setenv("OATD_AUDIT_HMAC_SECRET", "dedicated-audit-secret")
	if got := string(auditChainAnchorKey()); got != "dedicated-audit-secret" {
		t.Fatalf("explicit audit secret should be used as-is, got %q", got)
	}
}
