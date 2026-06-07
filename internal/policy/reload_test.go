package policy

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestEngineReloadSwapsApprovedTools(t *testing.T) {
	e := New(Config{ApprovedTools: []string{"alpha"}, ThreatPack: DefaultThreatPack()})

	beforeBeta := e.Evaluate(domain.Event{ID: "e1", Kind: domain.EventAgentToolCall, ToolName: "beta"})
	if !hasAlertRule(beforeBeta, "agent.tool.unapproved") {
		t.Fatal("beta should be unapproved before reload")
	}

	e.Reload(Config{ApprovedTools: []string{"beta"}, ThreatPack: DefaultThreatPack()})

	afterBeta := e.Evaluate(domain.Event{ID: "e2", Kind: domain.EventAgentToolCall, ToolName: "beta"})
	if hasAlertRule(afterBeta, "agent.tool.unapproved") {
		t.Fatal("beta should be approved after reload")
	}
	afterAlpha := e.Evaluate(domain.Event{ID: "e3", Kind: domain.EventAgentToolCall, ToolName: "alpha"})
	if !hasAlertRule(afterAlpha, "agent.tool.unapproved") {
		t.Fatal("alpha should be unapproved after reload")
	}
}

func TestEngineReloadSwapsEgressAllowlist(t *testing.T) {
	e := New(Config{ApprovedEgressHosts: []string{"approved.example.com"}, ThreatPack: DefaultThreatPack()})
	if !e.isApprovedEgress("https://approved.example.com/x") {
		t.Fatal("approved.example.com should be allowed before reload")
	}
	e.Reload(Config{ApprovedEgressHosts: []string{"other.example.com"}, ThreatPack: DefaultThreatPack()})
	if e.isApprovedEgress("https://approved.example.com/x") {
		t.Fatal("approved.example.com should no longer be allowed after reload")
	}
	if !e.isApprovedEgress("https://other.example.com/x") {
		t.Fatal("other.example.com should be allowed after reload")
	}
}
