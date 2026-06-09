package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// TestStoreConcurrentAccess hammers the in-memory store from many goroutines.
// It guards data integrity under load and is run under -race in CI to catch any
// data race in the persistence layer.
func TestStoreConcurrentAccess(t *testing.T) {
	s := New()
	const workers = 16
	const perWorker = 100
	now := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_ = s.AddEvent(domain.Event{
					ID: fmt.Sprintf("e-%d-%d", w, i), Timestamp: now,
					Kind: domain.EventAgentToolCall, AssetID: "host", ToolName: "tool",
				})
				_, _ = s.AddAlerts([]domain.Alert{{
					ID: fmt.Sprintf("al-%d-%d", w, i), AssetID: "host", RuleID: "r",
					Severity: domain.SeverityLow, CreatedAt: now,
				}})
				_ = s.AddAudit(domain.AuditEvent{
					ID: fmt.Sprintf("au-%d-%d", w, i), Timestamp: now,
					Action: "act", ResourceType: "res", Outcome: "ok",
				})
				_ = s.ListEvents()
				_ = s.ListAlerts()
				_, _, _, _, _ = s.Counts()
			}
		}(w)
	}
	wg.Wait()

	events, alerts, _, _, audits := s.Counts()
	if events != workers*perWorker {
		t.Fatalf("expected %d events, got %d", workers*perWorker, events)
	}
	if alerts != workers*perWorker {
		t.Fatalf("expected %d alerts, got %d", workers*perWorker, alerts)
	}
	if audits != workers*perWorker {
		t.Fatalf("expected %d audits, got %d", workers*perWorker, audits)
	}
}

// TestStoreTenantIsolation verifies one tenant cannot observe another tenant's
// events, alerts, or audits — a core multi-tenancy security property.
func TestStoreTenantIsolation(t *testing.T) {
	s := New()
	now := time.Now()

	if err := s.AddEvent(domain.Event{ID: "ea", Tenant: "a", Kind: domain.EventAgentToolCall, AssetID: "h", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEvent(domain.Event{ID: "eb", Tenant: "b", Kind: domain.EventAgentToolCall, AssetID: "h", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAlerts([]domain.Alert{{ID: "aa", Tenant: "a", AssetID: "h", RuleID: "r", Severity: domain.SeverityLow, CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAlerts([]domain.Alert{{ID: "ab", Tenant: "b", AssetID: "h", RuleID: "r", Severity: domain.SeverityLow, CreatedAt: now}}); err != nil {
		t.Fatal(err)
	}

	ea := s.ListEventsForTenant("a")
	if len(ea) != 1 || ea[0].Tenant != "a" {
		t.Fatalf("tenant a should see only its own event, got %+v", ea)
	}
	eb := s.ListEventsForTenant("b")
	if len(eb) != 1 || eb[0].Tenant != "b" {
		t.Fatalf("tenant b should see only its own event, got %+v", eb)
	}
	aa := s.ListAlertsForTenant("a")
	if len(aa) != 1 || aa[0].Tenant != "a" {
		t.Fatalf("tenant a should see only its own alert, got %+v", aa)
	}
}
