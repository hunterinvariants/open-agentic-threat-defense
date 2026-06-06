package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestStorePersistsAndLoadsSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	event := domain.Event{
		ID:        "evt-1",
		Timestamp: time.Now().UTC(),
		Kind:      domain.EventAgentToolCall,
		AssetID:   "asset-1",
		Hostname:  "asset-1",
		ToolName:  "shell_exec",
	}
	if err := s.AddEvent(event); err != nil {
		t.Fatalf("add event: %v", err)
	}

	alert := domain.Alert{
		ID:          "alert-1",
		Fingerprint: "rule:evt-1",
		RuleID:      "rule",
		Title:       "test alert",
		Severity:    domain.SeverityHigh,
		Status:      domain.AlertOpen,
		AssetID:     "asset-1",
		CreatedAt:   time.Now().UTC(),
		EventIDs:    []string{"evt-1"},
	}
	if _, err := s.AddAlerts([]domain.Alert{alert}); err != nil {
		t.Fatalf("add alert: %v", err)
	}

	action := domain.ResponseAction{
		ID:        "act-1",
		Type:      "isolate_host",
		Mode:      "dry-run",
		AssetID:   "asset-1",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.AddActions([]domain.ResponseAction{action}); err != nil {
		t.Fatalf("add action: %v", err)
	}

	loaded, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	events, alerts, assets, actions := loaded.Counts()
	if events != 1 || alerts != 1 || assets != 1 || actions != 1 {
		t.Fatalf("unexpected counts: events=%d alerts=%d assets=%d actions=%d", events, alerts, assets, actions)
	}
	if loaded.LastPersistenceError() != "" {
		t.Fatalf("unexpected persistence error: %s", loaded.LastPersistenceError())
	}
}

func TestStoreSkipsDuplicateAlertFingerprintsAfterLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	alert := domain.Alert{
		ID:          "alert-1",
		Fingerprint: "rule:evt-1",
		RuleID:      "rule",
		Title:       "test alert",
		Severity:    domain.SeverityHigh,
		Status:      domain.AlertOpen,
		AssetID:     "asset-1",
		CreatedAt:   time.Now().UTC(),
	}
	if _, err := s.AddAlerts([]domain.Alert{alert}); err != nil {
		t.Fatalf("add alert: %v", err)
	}

	loaded, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	added, err := loaded.AddAlerts([]domain.Alert{alert})
	if err != nil {
		t.Fatalf("add duplicate alert: %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("expected duplicate alert to be skipped, got %d", len(added))
	}
}

func TestStoreApprovesAction(t *testing.T) {
	s := New()
	action := domain.ResponseAction{
		ID:             "act-1",
		Type:           "isolate_host",
		Mode:           "dry-run",
		AssetID:        "asset-1",
		ApprovalStatus: "required",
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.AddActions([]domain.ResponseAction{action}); err != nil {
		t.Fatalf("add action: %v", err)
	}

	approved, ok, err := s.ApproveAction("act-1", "alice", time.Now().UTC())
	if err != nil {
		t.Fatalf("approve action: %v", err)
	}
	if !ok {
		t.Fatal("expected action to be found")
	}
	if approved.ApprovalStatus != "approved" || approved.ApprovedBy != "alice" || approved.ApprovedAt == nil {
		t.Fatalf("unexpected approved action: %#v", approved)
	}
}
