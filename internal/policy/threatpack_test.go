package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeTempManifest(t *testing.T) (string, []byte) {
	t.Helper()
	data, err := json.Marshal(DefaultThreatPack())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path, data
}

func TestThreatPackSignatureRoundTrip(t *testing.T) {
	t.Setenv("OATD_MANIFEST_HMAC_SECRET", "test-manifest-secret")
	path, data := writeTempManifest(t)

	// With a signing key configured, an unsigned manifest now fails closed
	// (previously a missing signature silently skipped verification).
	if _, err := LoadThreatPack(path); err == nil {
		t.Fatal("unsigned load must fail closed when a signing key is configured")
	}

	// After signing, the manifest verifies and loads.
	if _, err := SignThreatPackFile(path); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := LoadThreatPack(path); err != nil {
		t.Fatalf("signed load should succeed: %v", err)
	}

	// Tampering the manifest after signing must be detected.
	if err := os.WriteFile(path, append(data, ' '), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := LoadThreatPack(path); err == nil {
		t.Fatal("tampered manifest must fail signature verification")
	}
}

func TestThreatPackSignatureRequired(t *testing.T) {
	t.Setenv("OATD_MANIFEST_HMAC_SECRET", "test-manifest-secret")
	t.Setenv("OATD_MANIFEST_REQUIRE_SIGNED", "1")
	path, _ := writeTempManifest(t)

	// Required + missing signature -> error.
	if _, err := LoadThreatPack(path); err == nil {
		t.Fatal("required-but-unsigned manifest must fail")
	}

	// Required + valid signature -> ok.
	if _, err := SignThreatPackFile(path); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := LoadThreatPack(path); err != nil {
		t.Fatalf("required+signed load should succeed: %v", err)
	}
}

func TestThreatPackUnsignedNoKeyLoads(t *testing.T) {
	// No key configured: verification is skipped (backward compatible).
	t.Setenv("OATD_MANIFEST_HMAC_SECRET", "")
	t.Setenv("OATD_MANIFEST_REQUIRE_SIGNED", "")
	path, _ := writeTempManifest(t)
	if _, err := LoadThreatPack(path); err != nil {
		t.Fatalf("unsigned load without key should succeed: %v", err)
	}
}
