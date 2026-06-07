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

// TestReplayedTelemetryRaisesCorrelatedSequence drives a realistic multi-signal
// sequence through the full ingest -> policy -> correlator -> alert store path
// and asserts the per-event and correlated alerts are produced and queryable.
func TestReplayedTelemetryRaisesCorrelatedSequence(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	now := time.Now().UTC()
	asset := "host-replay-1"
	events := []domain.Event{
		{Kind: domain.EventProcessStart, AssetID: asset, Process: "cmd.exe", Command: "whoami /all", Timestamp: now.Add(-3 * time.Minute)},
		{Kind: domain.EventAgentToolCall, AssetID: asset, ToolName: "shell_exec", Command: "read env token material", Timestamp: now.Add(-2 * time.Minute)},
		{Kind: domain.EventNetworkFlow, AssetID: asset, Destination: "203.0.113.10:443", Timestamp: now.Add(-1 * time.Minute)},
	}
	body, _ := json.Marshal(events)

	req := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ingest: expected 202, got %d (%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		EventsIngested int            `json:"events_ingested"`
		Alerts         []domain.Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.EventsIngested != 3 {
		t.Fatalf("expected 3 events ingested, got %d", resp.EventsIngested)
	}

	got := map[string]bool{}
	for _, a := range resp.Alerts {
		got[a.RuleID] = true
	}
	for _, want := range []string{"agent.secret.exposure", "network.egress.unknown", "correlation.agentic.sequence"} {
		if !got[want] {
			t.Fatalf("expected alert rule %q, got %v", want, got)
		}
	}

	// Alerts are persisted and queryable.
	getRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), "correlation.agentic.sequence") {
		t.Fatalf("alerts query missing correlation: %d %s", getRec.Code, getRec.Body.String())
	}
}
