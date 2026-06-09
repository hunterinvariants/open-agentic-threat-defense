package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandlerHygiene exercises the error branches shared by the API handlers:
// wrong HTTP method and malformed bodies must produce clean 4xx, never a panic.
func TestHandlerHygiene(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Routes()

	do := func(method, path, body string) int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}

	if code := do(http.MethodGet, "/api/gateway/decide", ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/gateway/decide should be 405, got %d", code)
	}
	if code := do(http.MethodPost, "/api/gateway/decide", "{not valid json"); code != http.StatusBadRequest {
		t.Fatalf("malformed decide body should be 400, got %d", code)
	}
	if code := do(http.MethodPost, "/api/status", "{}"); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/status should be 405, got %d", code)
	}
}
