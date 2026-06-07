package policy

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestTenantPolicyScopesToolApproval(t *testing.T) {
	e := New(Config{ApprovedTools: []string{"shell"}, ApprovedEgressHosts: []string{"updates.example.com"}})
	if !e.toolApprovedForTenant("", "shell") {
		t.Fatal("global shell should be approved")
	}
	e.SetTenantPolicy(TenantPolicy{TenantID: "acme", ApprovedTools: []string{"deploy"}})
	if e.toolApprovedForTenant("acme", "shell") {
		t.Fatal("acme overlay should NOT approve shell")
	}
	if !e.toolApprovedForTenant("acme", "deploy") {
		t.Fatal("acme overlay should approve deploy")
	}
	if !e.toolApprovedForTenant("other", "shell") {
		t.Fatal("a tenant without an overlay falls back to the global list")
	}
}

func TestTenantPolicyScopesEgress(t *testing.T) {
	e := New(Config{ApprovedTools: []string{"shell"}, ApprovedEgressHosts: []string{"updates.example.com"}})
	if !e.egressApprovedForTenant("", "https://updates.example.com/x") {
		t.Fatal("global egress should be approved")
	}
	e.SetTenantPolicy(TenantPolicy{TenantID: "acme", ApprovedEgress: []string{"acme-cdn.example.net"}})
	if e.egressApprovedForTenant("acme", "https://updates.example.com/x") {
		t.Fatal("acme overlay should not approve the global host")
	}
	if !e.egressApprovedForTenant("acme", "https://acme-cdn.example.net/y") {
		t.Fatal("acme overlay should approve its own host")
	}
}

func TestTenantPolicyGatewayDecisionDeniesOverriddenTool(t *testing.T) {
	e := New(Config{ApprovedTools: []string{"shell"}})
	e.SetTenantPolicy(TenantPolicy{TenantID: "acme", ApprovedTools: []string{"deploy"}})

	denied := e.GateToolCall(domain.ToolCallRequest{ID: "r1", Tenant: "acme", ToolName: "shell", Actor: "agent"})
	if denied.Verdict != domain.GatewayDeny {
		t.Fatalf("tenant overlay must deny an unapproved tool, got %s", denied.Verdict)
	}
	allowed := e.GateToolCall(domain.ToolCallRequest{ID: "r2", Tenant: "other", ToolName: "shell", Actor: "agent"})
	if allowed.Verdict == domain.GatewayDeny {
		t.Fatalf("a tenant without an overlay should fall back to the global allow, got %s", allowed.Verdict)
	}
}

func TestTenantPolicyCRUD(t *testing.T) {
	e := NewDefault()
	if _, ok := e.SetTenantPolicy(TenantPolicy{TenantID: "  "}); ok {
		t.Fatal("blank tenant id must be rejected")
	}
	stored, ok := e.SetTenantPolicy(TenantPolicy{TenantID: "acme", ApprovedTools: []string{"Deploy", "deploy", " "}})
	if !ok || len(stored.ApprovedTools) != 1 || stored.ApprovedTools[0] != "deploy" {
		t.Fatalf("expected normalized+deduped tools, got %+v", stored)
	}
	if got, ok := e.TenantPolicy("acme"); !ok || got.TenantID != "acme" {
		t.Fatalf("expected to read back acme, got %+v ok=%v", got, ok)
	}
	if list := e.ListTenantPolicies(); len(list) != 1 {
		t.Fatalf("expected exactly 1 policy, got %d", len(list))
	}
	if !e.RemoveTenantPolicy("acme") {
		t.Fatal("first removal should succeed")
	}
	if e.RemoveTenantPolicy("acme") {
		t.Fatal("second removal should report not found")
	}
}
