package response

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func hasActionType(actions []domain.ResponseAction, t string) *domain.ResponseAction {
	for i := range actions {
		if actions[i].Type == t {
			return &actions[i]
		}
	}
	return nil
}

func TestPlanBaseline(t *testing.T) {
	actions := NewDryRun().Plan(domain.Alert{ID: "a1", AssetID: "h", Severity: domain.SeverityLow, RuleID: "process.start"})
	if len(actions) != 1 || actions[0].Type != "create_incident_ticket" {
		t.Fatalf("baseline should yield only an incident ticket, got %+v", actions)
	}
	if actions[0].Mode != "dry-run" {
		t.Fatalf("default mode should be dry-run, got %q", actions[0].Mode)
	}
}

func TestPlanHighSeverityIsolates(t *testing.T) {
	actions := NewDryRun().Plan(domain.Alert{ID: "a", AssetID: "h", Severity: domain.SeverityCritical, RuleID: "x"})
	if hasActionType(actions, "isolate_host") == nil {
		t.Fatalf("high severity should add isolate_host, got %+v", actions)
	}
}

func TestPlanEgressBlocks(t *testing.T) {
	actions := NewDryRun().Plan(domain.Alert{
		ID: "a", AssetID: "h", Severity: domain.SeverityLow, RuleID: "network.egress.unknown",
		Evidence: map[string]string{"destination": "evil.example"},
	})
	block := hasActionType(actions, "block_egress")
	if block == nil {
		t.Fatalf("egress rule should add block_egress, got %+v", actions)
	}
	if block.Target != "evil.example" {
		t.Fatalf("block_egress target should be the destination, got %q", block.Target)
	}
}

func TestPlanAgentToolDisables(t *testing.T) {
	actions := NewDryRun().Plan(domain.Alert{
		ID: "a", AssetID: "h", Severity: domain.SeverityLow, RuleID: "agent.tool.unapproved",
		Evidence: map[string]string{"tool": "rm"},
	})
	disable := hasActionType(actions, "disable_agent_tool")
	if disable == nil || disable.Target != "rm" {
		t.Fatalf("agent.tool rule should disable the tool, got %+v", actions)
	}
}

func TestPlanSecretRotates(t *testing.T) {
	actions := NewDryRun().Plan(domain.Alert{ID: "a", AssetID: "h", Severity: domain.SeverityLow, RuleID: "agent.secret.exposure"})
	if hasActionType(actions, "rotate_related_secrets") == nil {
		t.Fatalf("secret rule should add rotate_related_secrets, got %+v", actions)
	}
}

func TestPlanModeOverride(t *testing.T) {
	actions := (&Planner{Mode: "execute"}).Plan(domain.Alert{ID: "a", AssetID: "h", Severity: domain.SeverityLow, RuleID: "x"})
	if actions[0].Mode != "execute" {
		t.Fatalf("mode should carry through, got %q", actions[0].Mode)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if firstNonEmpty("", "", "x") != "x" {
		t.Fatal("firstNonEmpty should return the first non-empty value")
	}
	if firstNonEmpty("", "") != "" {
		t.Fatal("firstNonEmpty of all-empty should be empty")
	}
}
