package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGatewaySemaphoreConcurrentOverload drives the backpressure semaphore from
// many goroutines well past its cap. Every attempt must be cleanly granted or
// shed with 429 (never a crash), and — critically — the semaphore must not leak
// slots under concurrent acquire/release, so a fresh acquire still succeeds after
// the storm. Run under -race in CI, it guards the degradation path under load.
func TestGatewaySemaphoreConcurrentOverload(t *testing.T) {
	app, err := NewWithOptions(Options{GatewayMaxInFlight: 4})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	const workers = 64
	const iters = 50
	var granted, shed int64

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				rec := httptest.NewRecorder()
				release, ok := app.gatewayCriticalStart(rec)
				if ok {
					atomic.AddInt64(&granted, 1)
					release()
					continue
				}
				atomic.AddInt64(&shed, 1)
				if rec.Code != http.StatusTooManyRequests {
					t.Errorf("a shed request should be 429, got %d", rec.Code)
				}
			}
		}()
	}
	wg.Wait()

	total := int64(workers * iters)
	if granted+shed != total {
		t.Fatalf("every attempt should be granted or shed: granted=%d shed=%d total=%d", granted, shed, total)
	}
	if granted == 0 {
		t.Fatal("expected some grants under load")
	}

	// No slot leak: capacity must be fully available again after the storm.
	rec := httptest.NewRecorder()
	release, ok := app.gatewayCriticalStart(rec)
	if !ok {
		t.Fatal("the semaphore leaked slots: cannot acquire after concurrent overload")
	}
	release()
}
