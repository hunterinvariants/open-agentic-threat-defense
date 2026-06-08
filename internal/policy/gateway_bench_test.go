package policy

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// BenchmarkGateToolCall measures the raw cost of a single inline gateway
// decision (taint analysis, term matching, risk scoring, history) so the
// inline-PEP overhead can be quantified independent of HTTP.
func BenchmarkGateToolCall(b *testing.B) {
	engine := NewDefault()
	request := domain.ToolCallRequest{
		ID:       "bench",
		AssetID:  "host-1",
		Actor:    "bench-agent",
		ToolName: "asset_inventory",
		Command:  "whoami; net user; read api_key and ssh_key material",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.GateToolCall(request)
	}
}

func BenchmarkGateToolCallBenign(b *testing.B) {
	engine := NewDefault()
	request := domain.ToolCallRequest{
		ID:       "bench",
		AssetID:  "host-1",
		Actor:    "bench-agent",
		ToolName: "asset_inventory",
		Command:  "list assets",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.GateToolCall(request)
	}
}
