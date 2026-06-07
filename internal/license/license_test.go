package license

import (
	"testing"
	"time"
)

func TestLicenseIssueVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	token, err := Issue(License{
		Org:       "Acme",
		Edition:   "commercial",
		Features:  []string{"sso", "multi-tenant"},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	st := Evaluate(token, pub, time.Now().UTC())
	if !st.Valid {
		t.Fatalf("expected valid, got %+v", st)
	}
	if st.Org != "Acme" || st.Edition != "commercial" {
		t.Fatalf("unexpected license: %+v", st.License)
	}
	if !st.HasFeature("sso") || st.HasFeature("nope") {
		t.Fatal("feature check failed")
	}
}

func TestLicenseExpired(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	token, _ := Issue(License{Org: "Acme", ExpiresAt: time.Now().UTC().Add(-time.Hour)}, priv)
	st := Evaluate(token, pub, time.Now().UTC())
	if st.Valid || st.Reason != "license expired" {
		t.Fatalf("expected expired, got %+v", st)
	}
}

func TestLicenseTamperRejected(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	token, _ := Issue(License{Org: "Acme", Edition: "commercial"}, priv)
	tampered := "Z" + token[1:] // corrupt the payload segment
	if st := Evaluate(tampered, pub, time.Now().UTC()); st.Valid {
		t.Fatal("tampered token must be invalid")
	}
}

func TestLicenseWrongKeyRejected(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	otherPub, _, _ := GenerateKeyPair()
	token, _ := Issue(License{Org: "Acme"}, priv)
	if st := Evaluate(token, otherPub, time.Now().UTC()); st.Valid {
		t.Fatal("token verified with the wrong public key must be invalid")
	}
}

func TestCommunityDefault(t *testing.T) {
	st := Community()
	if st.Valid || st.Edition != "community" {
		t.Fatalf("unexpected community status: %+v", st)
	}
}
