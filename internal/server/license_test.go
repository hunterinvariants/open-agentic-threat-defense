package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/license"
)

func TestLicenseEndpointCommunityDefault(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/license", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var st license.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Valid || st.Edition != "community" {
		t.Fatalf("expected community default, got %+v", st)
	}
}

func TestLicenseEndpointValidCommercial(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	token, err := license.Issue(license.License{
		Org:       "Acme",
		Edition:   "commercial",
		Features:  []string{"sso"},
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	app, err := NewWithOptions(Options{LicenseToken: token, LicensePublicKey: pub})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/license", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var st license.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Valid || st.Org != "Acme" || !st.HasFeature("sso") {
		t.Fatalf("expected valid commercial license, got %+v", st)
	}
}
