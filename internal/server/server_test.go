package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteEndpointsRequireTokenWhenConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/demo", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWriteEndpointsAcceptBearerToken(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/demo", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestReadEndpointsDoNotRequireToken(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
