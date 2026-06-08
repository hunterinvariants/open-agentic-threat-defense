package store

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestPostgresPersistenceIntegration(t *testing.T) {
	dsn := os.Getenv("OATD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OATD_TEST_POSTGRES_DSN to run Postgres integration tests")
	}

	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	eventID := "it-evt-" + suffix
	alertID := "it-alert-" + suffix
	actionID := "it-act-" + suffix
	auditID := "it-aud-" + suffix
	assetID := "it-asset-" + suffix

	s, err := NewWithPostgres(dsn)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer cleanupPostgresIntegrationRows(t, s, eventID, alertID, actionID, auditID, assetID)
	if s.SchemaVersion() < 1 {
		t.Fatalf("expected postgres schema version, got %d", s.SchemaVersion())
	}
	if got := s.db.Stats().MaxOpenConnections; got != 10 {
		t.Fatalf("expected postgres pool max open conns 10, got %d", got)
	}

	event := domain.Event{
		ID:        eventID,
		Timestamp: time.Now().UTC(),
		Kind:      domain.EventAgentToolCall,
		AssetID:   assetID,
		Hostname:  assetID,
		ToolName:  "shell_exec",
	}
	if err := s.AddEvent(event); err != nil {
		t.Fatalf("add event: %v", err)
	}

	alert := domain.Alert{
		ID:          alertID,
		Fingerprint: "integration:" + eventID,
		RuleID:      "integration",
		Title:       "integration alert",
		Severity:    domain.SeverityHigh,
		Status:      domain.AlertOpen,
		AssetID:     assetID,
		CreatedAt:   time.Now().UTC(),
		EventIDs:    []string{eventID},
	}
	if _, err := s.AddAlerts([]domain.Alert{alert}); err != nil {
		t.Fatalf("add alert: %v", err)
	}

	action := domain.ResponseAction{
		ID:             actionID,
		Type:           "isolate_host",
		Mode:           "dry-run",
		AssetID:        assetID,
		ApprovalStatus: "required",
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.AddActions([]domain.ResponseAction{action}); err != nil {
		t.Fatalf("add action: %v", err)
	}
	if _, ok, err := s.ApproveAction(actionID, "integration", time.Now().UTC()); err != nil || !ok {
		t.Fatalf("approve action ok=%v err=%v", ok, err)
	}

	audit := domain.AuditEvent{
		ID:           auditID,
		Timestamp:    time.Now().UTC(),
		Actor:        "integration",
		Action:       "responses.approve",
		ResourceType: "response_action",
		ResourceID:   actionID,
		Outcome:      "accepted",
		Metadata:     map[string]string{"asset_id": assetID},
	}
	if err := s.AddAudit(audit); err != nil {
		t.Fatalf("add audit: %v", err)
	}
	snap := s.ExportSnapshot()
	if err := s.RestoreSnapshot(snap); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}

	loaded, err := NewWithPostgres(dsn)
	if err != nil {
		t.Fatalf("reload postgres store: %v", err)
	}
	defer loaded.Close()
	if loaded.SchemaVersion() != s.SchemaVersion() {
		t.Fatalf("unexpected reloaded schema version: got %d want %d", loaded.SchemaVersion(), s.SchemaVersion())
	}

	if !hasEvent(loaded.ListEvents(), eventID) {
		t.Fatalf("expected reloaded event %s", eventID)
	}
	if !hasAction(loaded.ListActions(), actionID, "approved") {
		t.Fatalf("expected reloaded approved action %s", actionID)
	}
	if !hasAudit(loaded.ListAudits(), auditID) {
		t.Fatalf("expected reloaded audit event %s", auditID)
	}
}

// H3: the Postgres audit-chain snapshot must re-derive validity from the event
// rows so that tampering with a non-head record is detected at runtime, instead
// of trusting the stored `valid` flag.
func TestPostgresAuditChainDetectsRecordTampering(t *testing.T) {
	dsn := os.Getenv("OATD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OATD_TEST_POSTGRES_DSN to run Postgres integration tests")
	}
	t.Setenv("OATD_AUDIT_HMAC_SECRET", "integration-audit-secret")

	s, err := NewWithPostgres(dsn)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	defer s.Close()

	// Isolate from any other integration data: start from an empty chain.
	if _, err := s.db.Exec(`DELETE FROM oatd_audit_events`); err != nil {
		t.Fatalf("clean audit events: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE oatd_audit_chain_state SET head_hash = '', chain_index = 0, anchor_hmac = '' WHERE id = 1`); err != nil {
		t.Fatalf("reset chain state: %v", err)
	}

	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	ids := []string{"tamper-a-" + suffix, "tamper-b-" + suffix, "tamper-c-" + suffix}
	defer func() {
		for _, id := range ids {
			_, _ = s.db.Exec(`DELETE FROM oatd_audit_events WHERE id = $1`, id)
		}
	}()
	for _, id := range ids {
		if err := s.AddAudit(domain.AuditEvent{
			ID:        id,
			Timestamp: time.Now().UTC(),
			Actor:     "tester",
			Action:    "test.write",
			Outcome:   "ok",
		}); err != nil {
			t.Fatalf("add audit %s: %v", id, err)
		}
	}

	if snap := s.AuditChain(); !snap.Valid || snap.Linked != len(ids) {
		t.Fatalf("expected a valid %d-record chain before tampering, got %+v", len(ids), snap)
	}

	// Tamper a NON-head record's content without updating its stored hash.
	if _, err := s.db.Exec(`UPDATE oatd_audit_events SET data = jsonb_set(data, '{outcome}', '"tampered"') WHERE id = $1`, ids[0]); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	if snap := s.AuditChain(); snap.Valid {
		t.Fatalf("expected the chain to be reported INVALID after DB tampering, got %+v", snap)
	}
}

// H4: assets are scoped by (tenant, id) end-to-end, so two tenants sharing an
// asset id persist and reload as separate, isolated records.
func TestPostgresAssetsAreTenantScoped(t *testing.T) {
	dsn := os.Getenv("OATD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OATD_TEST_POSTGRES_DSN to run Postgres integration tests")
	}
	s, err := NewWithPostgres(dsn)
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	if s.SchemaVersion() < 4 {
		t.Fatalf("expected the assets_tenant_scope migration (schema >= 4), got %d", s.SchemaVersion())
	}
	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	assetID := "shared-" + suffix
	tenantA, tenantB := "ta-"+suffix, "tb-"+suffix
	evtA, evtB := "evt-"+tenantA, "evt-"+tenantB
	defer func() {
		_, _ = s.db.Exec(`DELETE FROM oatd_assets WHERE id = $1`, assetID)
		_, _ = s.db.Exec(`DELETE FROM oatd_events WHERE id IN ($1, $2)`, evtA, evtB)
		_ = s.Close()
	}()

	if err := s.AddEvent(domain.Event{ID: evtA, Tenant: tenantA, Kind: domain.EventAgentToolCall, AssetID: assetID, Hostname: assetID, SourceIP: "10.0.0.1", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatalf("add event a: %v", err)
	}
	if err := s.AddEvent(domain.Event{ID: evtB, Tenant: tenantB, Kind: domain.EventAgentToolCall, AssetID: assetID, Hostname: assetID, SourceIP: "10.9.9.9", Timestamp: time.Now().UTC()}); err != nil {
		t.Fatalf("add event b: %v", err)
	}

	// Reload from the database to exercise the tenant-keyed persist and load.
	loaded, err := NewWithPostgres(dsn)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	defer loaded.Close()

	a := loaded.ListAssetsForTenant(tenantA)
	b := loaded.ListAssetsForTenant(tenantB)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("each tenant must reload exactly its own asset, got a=%d b=%d", len(a), len(b))
	}
	if !contains(a[0].IPs, "10.0.0.1") || contains(a[0].IPs, "10.9.9.9") {
		t.Fatalf("cross-tenant asset leak after reload: %+v", a[0].IPs)
	}
}

func cleanupPostgresIntegrationRows(t *testing.T, s *Store, ids ...string) {
	t.Helper()
	if s == nil || s.db == nil {
		return
	}
	for _, table := range []string{"oatd_events", "oatd_alerts", "oatd_actions", "oatd_audit_events", "oatd_assets"} {
		if _, err := s.db.Exec("DELETE FROM "+table+" WHERE id IN ($1, $2, $3, $4, $5)", ids[0], ids[1], ids[2], ids[3], ids[4]); err != nil {
			t.Logf("cleanup %s: %v", table, err)
		}
	}
	_ = s.Close()
}

func hasEvent(events []domain.Event, id string) bool {
	for _, event := range events {
		if event.ID == id {
			return true
		}
	}
	return false
}

func hasAction(actions []domain.ResponseAction, id string, approvalStatus string) bool {
	for _, action := range actions {
		if action.ID == id && action.ApprovalStatus == approvalStatus {
			return true
		}
	}
	return false
}

func hasAudit(audits []domain.AuditEvent, id string) bool {
	for _, audit := range audits {
		if audit.ID == id {
			return true
		}
	}
	return false
}
