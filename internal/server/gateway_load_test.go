package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestGatewayDecideConcurrentLoad fires many concurrent decisions to confirm the
// inline gateway stays correct under load: every response is a valid decision or
// explicit backpressure, never a crash or unexpected error. Run under -race in
// CI, it also guards against data races on the decision path.
func TestGatewayDecideConcurrentLoad(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Routes()
	body := `{"asset_id":"h","actor":"load-agent","tool_name":"asset_inventory","command":"list assets"}`

	const workers = 32
	const each = 50
	var ok, backpressure, unexpected int64

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(body))
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				switch rec.Code {
				case http.StatusOK, http.StatusAccepted:
					atomic.AddInt64(&ok, 1)
				case http.StatusTooManyRequests, http.StatusServiceUnavailable:
					atomic.AddInt64(&backpressure, 1)
				default:
					atomic.AddInt64(&unexpected, 1)
				}
			}
		}()
	}
	wg.Wait()

	if unexpected != 0 {
		t.Fatalf("%d requests returned an unexpected status under load", unexpected)
	}
	if ok == 0 {
		t.Fatalf("expected successful decisions under load (ok=%d backpressure=%d)", ok, backpressure)
	}
}
