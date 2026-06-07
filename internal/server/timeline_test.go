package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestTimelineMergesAndSortsByTime(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	now := time.Now().UTC()
	asset := "tl-1"
	events := []domain.Event{
		{Kind: domain.EventAgentToolCall, AssetID: asset, ToolName: "shell_exec", Command: "read env token", Timestamp: now.Add(-2 * time.Minute)},
		{Kind: domain.EventNetworkFlow, AssetID: asset, Destination: "203.0.113.5:443", Timestamp: now.Add(-1 * time.Minute)},
	}
	body, _ := json.Marshal(events)
	app.Routes().ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(string(body))))

	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/timeline?asset_id=tl-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("timeline: %d (%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		AssetID string `json:"asset_id"`
		Entries []struct {
			Timestamp time.Time `json:"timestamp"`
			Kind      string    `json:"kind"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Entries) < 3 {
		t.Fatalf("expected events + alerts in the timeline, got %d entries", len(resp.Entries))
	}

	kinds := map[string]bool{}
	for i, e := range resp.Entries {
		kinds[e.Kind] = true
		if i > 0 && e.Timestamp.Before(resp.Entries[i-1].Timestamp) {
			t.Fatal("timeline entries must be sorted ascending by timestamp")
		}
	}
	if !kinds["event"] || !kinds["alert"] {
		t.Fatalf("expected event and alert kinds, got %v", kinds)
	}

	// asset_id is required.
	bad := httptest.NewRecorder()
	app.Routes().ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/api/timeline", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("missing asset_id should be 400, got %d", bad.Code)
	}
}
