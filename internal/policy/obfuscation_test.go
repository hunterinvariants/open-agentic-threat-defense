package policy

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// L2: the obfuscation decoder must peel multiple encoding layers and handle hex,
// so an attacker cannot evade the matcher by double-encoding a flagged term.
func TestDecodeGatewayCandidatesMultiLayer(t *testing.T) {
	inner := base64.StdEncoding.EncodeToString([]byte("password"))
	double := base64.StdEncoding.EncodeToString([]byte(inner))
	if !sliceContains(decodeGatewayCandidates(double), "password") {
		t.Fatalf("double-base64 should decode to 'password', got %v", decodeGatewayCandidates(double))
	}

	hexTok := hex.EncodeToString([]byte("password"))
	if !sliceContains(decodeGatewayCandidates(hexTok), "password") {
		t.Fatalf("hex should decode to 'password', got %v", decodeGatewayCandidates(hexTok))
	}
}

func sliceContains(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}
