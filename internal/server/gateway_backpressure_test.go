package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// H5: gateway backpressure is an in-process semaphore that returns 429 when the
// in-flight cap is reached and frees the slot on release — without pinning a DB
// connection per request.
func TestGatewayBackpressureReturns429WhenSaturated(t *testing.T) {
	app, err := NewWithOptions(Options{GatewayMaxInFlight: 1})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	rec1 := httptest.NewRecorder()
	release, ok := app.gatewayCriticalStart(rec1)
	if !ok {
		t.Fatal("first gateway slot should be granted")
	}

	// The single slot is taken; the next request must be shed with 429.
	rec2 := httptest.NewRecorder()
	if _, ok := app.gatewayCriticalStart(rec2); ok {
		t.Fatal("second gateway slot must be rejected while saturated")
	}
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when saturated, got %d", rec2.Code)
	}

	// Releasing the slot makes capacity available again.
	release()
	rec3 := httptest.NewRecorder()
	release3, ok := app.gatewayCriticalStart(rec3)
	if !ok {
		t.Fatal("gateway slot should be available again after release")
	}
	release3()
}
