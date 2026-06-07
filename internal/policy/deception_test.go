package policy

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestDeceptionRegistryCRUDAndMatch(t *testing.T) {
	e := NewDefault()
	if len(e.ListDeceptionTokens()) != 0 {
		t.Fatal("registry should start empty")
	}

	tok, err := e.AddDeceptionToken(domain.DeceptionToken{Name: "canary-aws", Kind: "secret", Value: "AKIACANARY12345"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if tok.ID == "" {
		t.Fatal("expected a generated id")
	}
	if len(e.ListDeceptionTokens()) != 1 {
		t.Fatalf("expected 1 token, got %d", len(e.ListDeceptionTokens()))
	}

	// Referencing the canary value must raise a deception hit (which the gateway denies).
	hit := e.Evaluate(domain.Event{ID: "e1", Kind: domain.EventAgentToolCall, ToolName: "asset_inventory", Command: "echo AKIACANARY12345"})
	if !hasAlertRule(hit, "deception.canary.hit") {
		t.Fatal("expected canary hit on the registered value")
	}

	// Obfuscated with separators should still match via compaction.
	obf := e.Evaluate(domain.Event{ID: "e2", Kind: domain.EventAgentToolCall, ToolName: "x", Command: "AKIA-CANARY-12345"})
	if !hasAlertRule(obf, "deception.canary.hit") {
		t.Fatal("expected canary hit on the obfuscated value")
	}

	// Empty value is rejected.
	if _, err := e.AddDeceptionToken(domain.DeceptionToken{Value: "  "}); err == nil {
		t.Fatal("expected error for empty value")
	}

	// After removal there is no match.
	if !e.RemoveDeceptionToken(tok.ID) {
		t.Fatal("expected remove to succeed")
	}
	gone := e.Evaluate(domain.Event{ID: "e3", Kind: domain.EventAgentToolCall, ToolName: "x", Command: "echo AKIACANARY12345"})
	if hasAlertRule(gone, "deception.canary.hit") {
		t.Fatal("should not match after removal")
	}
}

func TestDeceptionSeedFromConfig(t *testing.T) {
	e := New(Config{
		ThreatPack:      DefaultThreatPack(),
		DeceptionTokens: []domain.DeceptionToken{{Name: "honey", Value: "HONEYVALUE99"}},
	})
	if len(e.ListDeceptionTokens()) != 1 {
		t.Fatalf("expected seeded token, got %d", len(e.ListDeceptionTokens()))
	}
	hit := e.Evaluate(domain.Event{ID: "e1", Kind: domain.EventAgentToolCall, ToolName: "x", Command: "read HONEYVALUE99"})
	if !hasAlertRule(hit, "deception.canary.hit") {
		t.Fatal("expected canary hit on seeded value")
	}
}
