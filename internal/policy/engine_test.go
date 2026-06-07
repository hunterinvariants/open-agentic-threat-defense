package policy

import (
	"strings"
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

func TestGateToolCallAllowsApprovedTool(t *testing.T) {
	engine := NewDefault()

	decision := engine.GateToolCall(domain.ToolCallRequest{
		ID:       "gw-1",
		AssetID:  "host-1",
		Actor:    "agent-1",
		ToolName: "asset_inventory",
		Command:  "list hosts",
	})

	if decision.Verdict != domain.GatewayAllow {
		t.Fatalf("expected allow, got %s", decision.Verdict)
	}
	if len(decision.Alerts) != 0 {
		t.Fatalf("expected no alerts, got %#v", decision.Alerts)
	}
}

func TestGateToolCallRequiresApprovalForSecrets(t *testing.T) {
	engine := NewDefault()

	decision := engine.GateToolCall(domain.ToolCallRequest{
		ID:        "gw-1",
		AssetID:   "host-1",
		Actor:     "agent-1",
		ToolName:  "asset_inventory",
		Command:   "inspect inventory",
		Arguments: "token=abc123",
	})

	if decision.Verdict != domain.GatewayRequireApproval {
		t.Fatalf("expected approval, got %s", decision.Verdict)
	}
	if !hasAlertRule(decision.Alerts, "agent.secret.exposure") {
		t.Fatalf("expected secret exposure alert, got %#v", decision.Alerts)
	}
}

func TestGateToolCallRequiresApprovalForObfuscatedSecrets(t *testing.T) {
	engine := NewDefault()

	decision := engine.GateToolCall(domain.ToolCallRequest{
		ID:        "gw-1",
		AssetID:   "host-1",
		Actor:     "agent-1",
		ToolName:  "asset_inventory",
		Command:   "inspect inventory",
		Arguments: `s\ecret=c2VjcmV0`,
	})

	if decision.Verdict != domain.GatewayRequireApproval {
		t.Fatalf("expected approval, got %s", decision.Verdict)
	}
	if !strings.Contains(decision.Reason, "obfuscated") {
		t.Fatalf("expected obfuscated reason, got %q", decision.Reason)
	}
}

func TestGateToolCallRequiresApprovalForBase64Secrets(t *testing.T) {
	engine := NewDefault()

	decision := engine.GateToolCall(domain.ToolCallRequest{
		ID:        "gw-1",
		AssetID:   "host-1",
		Actor:     "agent-1",
		ToolName:  "asset_inventory",
		Command:   "inspect inventory",
		Arguments: "payload=c2VjcmV0",
	})

	if decision.Verdict != domain.GatewayRequireApproval {
		t.Fatalf("expected approval, got %s", decision.Verdict)
	}
	if !hasAlertRule(decision.Alerts, "agent.secret.exposure") {
		t.Fatalf("expected secret exposure alert, got %#v", decision.Alerts)
	}
}

func TestGateToolCallDeniesUnapprovedTool(t *testing.T) {
	engine := NewDefault()

	decision := engine.GateToolCall(domain.ToolCallRequest{
		ID:       "gw-1",
		AssetID:  "host-1",
		Actor:    "agent-1",
		ToolName: "shell_exec",
		Command:  "read env token",
	})

	if decision.Verdict != domain.GatewayDeny {
		t.Fatalf("expected deny, got %s", decision.Verdict)
	}
	if !hasAlertRule(decision.Alerts, "agent.tool.unapproved") {
		t.Fatalf("expected unapproved tool alert, got %#v", decision.Alerts)
	}
}
