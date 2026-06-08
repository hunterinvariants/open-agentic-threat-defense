package policy

import (
	"path/filepath"
	"testing"
)

// L1: when a signing key is configured, a missing signature must fail closed
// rather than silently skipping verification.
func TestVerifyThreatPackSignatureFailsClosedWhenKeySetButSigMissing(t *testing.T) {
	t.Setenv("OATD_MANIFEST_HMAC_SECRET", "test-signing-key")
	t.Setenv("OATD_MANIFEST_REQUIRE_SIGNED", "")
	path := filepath.Join(t.TempDir(), "manifest.json") // no .sig alongside it
	if err := verifyThreatPackSignature(path, []byte(`{"name":"x"}`)); err == nil {
		t.Fatal("expected fail-closed when a key is configured but the signature is missing")
	}
}

// Without a key and without requiring signatures, loading is permitted (warned).
func TestVerifyThreatPackSignatureAllowsUnsignedWhenNoKey(t *testing.T) {
	t.Setenv("OATD_MANIFEST_HMAC_SECRET", "")
	t.Setenv("OATD_MANIFEST_REQUIRE_SIGNED", "")
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := verifyThreatPackSignature(path, []byte(`{"name":"x"}`)); err != nil {
		t.Fatalf("unsigned load without a key should be permitted, got %v", err)
	}
}
