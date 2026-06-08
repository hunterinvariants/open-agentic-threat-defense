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
