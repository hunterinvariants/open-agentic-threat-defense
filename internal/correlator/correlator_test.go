package correlator

import (
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestEvaluateDetectsAgenticSequence(t *testing.T) {
	now := time.Now().UTC()
	c := New(30 * time.Minute)

	alerts := c.Evaluate([]domain.Event{
		{ID: "evt-1", Timestamp: now.Add(-4 * time.Minute), Kind: domain.EventProcessStart, AssetID: "host-1", Command: "whoami && ipconfig /all"},
		{ID: "evt-2", Timestamp: now.Add(-3 * time.Minute), Kind: domain.EventProcessStart, AssetID: "host-1", Command: "read env token"},
		{ID: "evt-3", Timestamp: now.Add(-2 * time.Minute), Kind: domain.EventAgentToolCall, AssetID: "host-1", ToolName: "shell_exec"},
		{ID: "evt-4", Timestamp: now.Add(-1 * time.Minute), Kind: domain.EventNetworkFlow, AssetID: "host-1", Destination: "203.0.113.50:443"},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "correlation.agentic.sequence" {
		t.Fatalf("expected correlation.agentic.sequence, got %s", alerts[0].RuleID)
	}
}
