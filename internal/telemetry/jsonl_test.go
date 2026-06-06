package telemetry

import (
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestReadJSONL(t *testing.T) {
	input := strings.NewReader(`
{"kind":"agent_tool_call","asset_id":"agent-1","tool_name":"shell_exec"}

{"kind":"network_flow","asset_id":"agent-1","destination":"203.0.113.10:443"}
`)

	events, err := ReadJSONL(input)
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Kind != domain.EventAgentToolCall {
		t.Fatalf("unexpected first kind: %s", events[0].Kind)
	}
}

func TestReadJSONLReportsLineNumbers(t *testing.T) {
	input := strings.NewReader("{\"kind\":\"network_flow\"}\nnot-json\n")

	_, err := ReadJSONL(input)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("expected line number in error, got %v", err)
	}
}
