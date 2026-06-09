package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestGatewayHistoryBounded(t *testing.T) {
	origMax, origBatch := maxGatewayHistoryEntries, gatewayHistoryEvictBatch
	maxGatewayHistoryEntries, gatewayHistoryEvictBatch = 100, 20
	defer func() { maxGatewayHistoryEntries, gatewayHistoryEvictBatch = origMax, origBatch }()

	engine := NewDefault()
	for i := 0; i < 500; i++ {
		engine.GateToolCall(domain.ToolCallRequest{
			ID: fmt.Sprintf("h-%d", i), AssetID: "host", Actor: "a",
			ToolName: "asset_inventory", Command: "list",
			Metadata: map[string]string{"run_id": fmt.Sprintf("run-%d", i)},
		})
	}

	engine.historyMu.Lock()
	size := len(engine.history)
	engine.historyMu.Unlock()
	if size > maxGatewayHistoryEntries {
		t.Fatalf("history not bounded: %d > %d distinct keys", size, maxGatewayHistoryEntries)
	}
}

func TestEvictOldestHistory(t *testing.T) {
	engine := NewDefault()
	base := time.Now()
	engine.historyMu.Lock()
	engine.history["old"] = &gatewayHistoryState{LastSeen: base.Add(-2 * time.Hour)}
	engine.history["mid"] = &gatewayHistoryState{LastSeen: base.Add(-1 * time.Hour)}
	engine.history["new"] = &gatewayHistoryState{LastSeen: base}
	engine.evictOldestHistoryLocked(1)
	_, oldThere := engine.history["old"]
	_, newThere := engine.history["new"]
	engine.historyMu.Unlock()

	if oldThere {
		t.Fatal("the oldest entry should have been evicted")
	}
	if !newThere {
		t.Fatal("the newest entry should remain")
	}
}
