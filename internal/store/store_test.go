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
	events, alerts, assets, actions, audits := loaded.Counts()
	if events != 1 || alerts != 1 || assets != 1 || actions != 1 || audits != 0 {
		t.Fatalf("unexpected counts: events=%d alerts=%d assets=%d actions=%d audits=%d", events, alerts, assets, actions, audits)
	}
	if loaded.LastPersistenceError() != "" {
		t.Fatalf("unexpected persistence error: %s", loaded.LastPersistenceError())
	}
}

func TestStorePersistsAndLoadsAuditSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	audit := domain.AuditEvent{
		ID:           "aud-1",
		Timestamp:    time.Now().UTC(),
		Actor:        "alice",
		Action:       "responses.approve",
		ResourceType: "response_action",
		ResourceID:   "act-1",
		Outcome:      "accepted",
		Metadata:     map[string]string{"asset_id": "asset-1"},
	}
	if err := s.AddAudit(audit); err != nil {
		t.Fatalf("add audit: %v", err)
	}
	chain := s.AuditChain()
	if !chain.Valid || chain.Total != 1 || chain.Linked != 1 || chain.Head == "" {
		t.Fatalf("unexpected audit chain after add: %#v", chain)
	}

	loaded, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	audits := loaded.ListAudits()
	if len(audits) != 1 || audits[0].Actor != "alice" || audits[0].Action != "responses.approve" {
		t.Fatalf("unexpected audit events: %#v", audits)
	}
	loadedChain := loaded.AuditChain()
	if !loadedChain.Valid || loadedChain.Head == "" || loadedChain.Total != 1 {
		t.Fatalf("unexpected loaded chain: %#v", loadedChain)
	}
}

func TestStoreExportsAndRestoresSnapshot(t *testing.T) {
	s := New()
	event := domain.Event{
		ID:        "evt-1",
		Timestamp: time.Now().UTC(),
		Kind:      domain.EventFinding,
		AssetID:   "asset-1",
		Hostname:  "asset-1",
	}
	if err := s.AddEvent(event); err != nil {
		t.Fatalf("add event: %v", err)
	}
	snap := s.ExportSnapshot()

	restored := New()
	if err := restored.RestoreSnapshot(snap); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}
	events, alerts, assets, actions, audits := restored.Counts()
	if events != 1 || alerts != 0 || assets != 1 || actions != 0 || audits != 0 {
		t.Fatalf("unexpected restored counts: events=%d alerts=%d assets=%d actions=%d audits=%d", events, alerts, assets, actions, audits)
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

func TestStoreAppliesRetentionWindow(t *testing.T) {
	s := New()
	oldEvent := domain.Event{
		ID:        "evt-old",
		Timestamp: time.Now().UTC().Add(-2 * time.Hour),
		Kind:      domain.EventFinding,
		AssetID:   "asset-1",
		Hostname:  "asset-1",
	}
	newEvent := domain.Event{
		ID:        "evt-new",
		Timestamp: time.Now().UTC(),
		Kind:      domain.EventFinding,
		AssetID:   "asset-1",
		Hostname:  "asset-1",
	}
	if err := s.AddEvent(oldEvent); err != nil {
		t.Fatalf("add old event: %v", err)
	}
	if err := s.AddEvent(newEvent); err != nil {
		t.Fatalf("add new event: %v", err)
	}
	if err := s.SetRetention(30 * time.Minute); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	events := s.ListEvents()
	if len(events) != 1 || events[0].ID != "evt-new" {
		t.Fatalf("expected only retained event, got %#v", events)
	}
	eventsCount, _, assetsCount, _, _ := s.Counts()
	if eventsCount != 1 || assetsCount != 1 {
		t.Fatalf("unexpected counts after retention: events=%d assets=%d", eventsCount, assetsCount)
	}
}

func TestLastPersistenceErrorIsRedacted(t *testing.T) {
	s := New()
	s.lastErr = "open /etc/passwd: permission denied"
	got := s.LastPersistenceError()
	if got == "" || got == s.lastErr {
		t.Fatalf("expected redacted persistence error, got %q", got)
	}
}
