package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// L7: internal (500) errors must not reflect store/driver detail to clients.
func TestWriteErrorRedactsInternalErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusInternalServerError, errors.New("pq: relation oatd_secret does not exist"))
	body := rec.Body.String()
	if strings.Contains(body, "oatd_secret") {
		t.Fatalf("500 must not leak internal detail: %s", body)
	}
	if !strings.Contains(body, "internal server error") {
		t.Fatalf("expected a generic 500 message, got %s", body)
	}

	// Client (4xx) errors keep their descriptive message.
	rec2 := httptest.NewRecorder()
	writeError(rec2, http.StatusBadRequest, errors.New("missing field xyz"))
	if !strings.Contains(rec2.Body.String(), "missing field xyz") {
		t.Fatalf("4xx should keep its message, got %s", rec2.Body.String())
	}
}

// Log-injection: control characters in user-influenced strings must not be able
// to forge or split log lines.
func TestSanitizeLogValue(t *testing.T) {
	got := sanitizeLogValue("user\ninjected\rline\x00null\ttab")
	if strings.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control characters not stripped: %q", got)
	}
	if !strings.Contains(got, "\t") {
		t.Fatalf("tab should be preserved, got %q", got)
	}
}
