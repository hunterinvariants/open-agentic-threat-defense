package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestValidationResultEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validation-last.json")
	sample := `{"total":2,"passed":2,"missed":0,"false_positives":0,"results":[` +
		`{"name":"benign-baseline","technique":"-","tactic":"-","want":"allow","got":"allow","at_least":false,"pass":true},` +
		`{"name":"secret-in-context","technique":"T1552.001","tactic":"Credential-Access","want":">=require_approval","got":"require_approval","at_least":true,"pass":true}]}`
	if err := os.WriteFile(path, []byte(sample), 0o640); err != nil {
		t.Fatal(err)
	}

	app, err := NewWithOptions(Options{ValidationResultPath: path})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/gateway/validation", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		RanAt  string          `json:"ran_at"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if resp.RanAt == "" {
		t.Fatal("expected ran_at to be populated")
	}
	var result struct {
		Total  int `json:"total"`
		Passed int `json:"passed"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	if result.Total != 2 || result.Passed != 2 {
		t.Fatalf("unexpected result totals: %+v", result)
	}
}

func TestValidationResultEndpointNotConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/gateway/validation", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when unconfigured, got %d", rec.Code)
	}
}

func TestValidationResultEndpointMissingFile(t *testing.T) {
	dir := t.TempDir()
	app, err := NewWithOptions(Options{ValidationResultPath: filepath.Join(dir, "absent.json")})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/gateway/validation", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when file missing, got %d", rec.Code)
	}
}
