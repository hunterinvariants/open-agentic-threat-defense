package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// I5: oversized request bodies are rejected by the body-limit middleware rather
// than driving proportional allocation in the JSON decoders.
func TestRequestBodyLimitRejectsOversized(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	oversized := strings.Repeat("a", 5<<20) // 5 MiB > 4 MiB limit
	body := `{"tool_name":"x","command":"` + oversized + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(body))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("oversized body must be rejected with a 4xx, got %d", rec.Code)
	}
}
