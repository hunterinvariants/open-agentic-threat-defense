package policy

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestEvaluateFlagsUnapprovedAgentTool(t *testing.T) {
	engine := NewDefault()

	alerts := engine.Evaluate(domain.Event{
		ID:       "evt-1",
		Kind:     domain.EventAgentToolCall,
		AssetID:  "host-1",
		ToolName: "shell_exec",
		Command:  "read inventory",
	})

	if len(alerts) == 0 {
		t.Fatal("expected at least one alert")
	}
	if alerts[0].RuleID != "agent.tool.unapproved" {
		t.Fatalf("expected agent.tool.unapproved, got %s", alerts[0].RuleID)
	}
}

func TestEvaluateAllowsApprovedTool(t *testing.T) {
	engine := NewDefault()

	alerts := engine.Evaluate(domain.Event{
		ID:       "evt-1",
		Kind:     domain.EventAgentToolCall,
		AssetID:  "host-1",
		ToolName: "asset_inventory",
		Command:  "list hosts",
	})

	for _, alert := range alerts {
		if alert.RuleID == "agent.tool.unapproved" {
			t.Fatal("did not expect unapproved tool alert")
		}
	}
}

func TestEvaluateAllowsConfiguredTool(t *testing.T) {
	engine := New(Config{
		ApprovedTools: []string{"shell_exec"},
	})

	alerts := engine.Evaluate(domain.Event{
		ID:       "evt-1",
		Kind:     domain.EventAgentToolCall,
		AssetID:  "host-1",
		ToolName: "shell_exec",
		Command:  "read inventory",
	})

	for _, alert := range alerts {
		if alert.RuleID == "agent.tool.unapproved" {
			t.Fatal("did not expect unapproved tool alert")
		}
	}
}

func TestEvaluateAllowsConfiguredEgressHost(t *testing.T) {
	engine := New(Config{
		ApprovedEgressHosts: []string{"example.com"},
	})

	alerts := engine.Evaluate(domain.Event{
		ID:          "evt-1",
		Kind:        domain.EventNetworkFlow,
		AssetID:     "host-1",
		Destination: "https://example.com/models",
	})

	for _, alert := range alerts {
		if alert.RuleID == "network.egress.unknown" {
			t.Fatal("did not expect unknown egress alert")
		}
	}
}
