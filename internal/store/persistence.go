package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const snapshotVersion = 1

type Snapshot struct {
	Version int                     `json:"version"`
	SavedAt time.Time               `json:"saved_at"`
	Events  []domain.Event          `json:"events"`
	Alerts  []domain.Alert          `json:"alerts"`
	Actions []domain.ResponseAction `json:"actions"`
	Audits  []domain.AuditEvent     `json:"audits"`
	Assets  map[string]domain.Asset `json:"assets"`
}

func NewWithPath(path string) (*Store, error) {
	s := New()
	s.path = path
	if path == "" {
		return s, nil
	}
	s.mode = "file"

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap.Version > snapshotVersion {
		return nil, errors.New("snapshot version is newer than this binary supports")
	}

	s.events = append([]domain.Event(nil), snap.Events...)
	s.alerts = append([]domain.Alert(nil), snap.Alerts...)
	s.actions = append([]domain.ResponseAction(nil), snap.Actions...)
	s.audits = append([]domain.AuditEvent(nil), snap.Audits...)
	if snap.Assets != nil {
		s.assets = snap.Assets
	} else {
		s.rebuildAssetsLocked()
	}
	s.rebuildFingerprintsLocked()
	s.rebuildAuditChainLocked()
	return s, nil
}

func (s *Store) ExportSnapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() Snapshot {
	return Snapshot{
		Version: snapshotVersion,
		SavedAt: time.Now().UTC(),
		Events:  append([]domain.Event(nil), s.events...),
		Alerts:  append([]domain.Alert(nil), s.alerts...),
		Actions: append([]domain.ResponseAction(nil), s.actions...),
		Audits:  append([]domain.AuditEvent(nil), s.audits...),
		Assets:  cloneAssets(s.assets),
	}
}

func (s *Store) RestoreSnapshot(snap Snapshot) error {
	if snap.Version > snapshotVersion {
		return errors.New("snapshot version is newer than this binary supports")
	}

	restored := New()
	restored.events = append([]domain.Event(nil), snap.Events...)
	restored.alerts = append([]domain.Alert(nil), snap.Alerts...)
	restored.actions = append([]domain.ResponseAction(nil), snap.Actions...)
	restored.audits = append([]domain.AuditEvent(nil), snap.Audits...)
	if snap.Assets != nil {
		restored.assets = cloneAssets(snap.Assets)
	} else {
		restored.rebuildAssetsLocked()
	}
	restored.rebuildFingerprintsLocked()

	if restored.db != nil {
		return errors.New("unexpected db on restored snapshot")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		if err := s.postgresRestoreSnapshotLocked(restored.snapshotLocked()); err != nil {
			return err
		}
	}

	s.events = append([]domain.Event(nil), restored.events...)
	s.alerts = append([]domain.Alert(nil), restored.alerts...)
	s.actions = append([]domain.ResponseAction(nil), restored.actions...)
	s.audits = append([]domain.AuditEvent(nil), restored.audits...)
	s.assets = cloneAssets(restored.assets)
	s.rebuildFingerprintsLocked()
	s.lastErr = ""
	if err := s.enforceRetentionLocked(); err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	if s.path == "" || s.mode == "postgres" {
		s.lastErr = ""
		return nil
	}

	snap := s.snapshotLocked()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		s.lastErr = err.Error()
		return err
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		s.lastErr = err.Error()
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		s.lastErr = err.Error()
		return err
	}
	if err := replaceFile(tmp, s.path); err != nil {
		s.lastErr = err.Error()
		return err
	}

	s.lastErr = ""
	return nil
}

func (s *Store) persistEventLocked(event domain.Event) error {
	if s.db != nil {
		return s.postgresPersistEventLocked(event)
	}
	return nil
}

func (s *Store) persistAlertsLocked(alerts []domain.Alert) error {
	if s.db != nil {
		return s.postgresPersistAlertsLocked(alerts)
	}
	return nil
}

func (s *Store) persistActionsLocked(actions []domain.ResponseAction) error {
	if s.db != nil {
		return s.postgresPersistActionsLocked(actions)
	}
	return nil
}

func (s *Store) persistAuditLocked(event domain.AuditEvent) error {
	if s.db != nil {
		return s.postgresPersistAuditLocked(event)
	}
	return nil
}

func (s *Store) postgresRestoreSnapshotLocked(snap Snapshot) error {
	if s.db == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
TRUNCATE TABLE oatd_events, oatd_alerts, oatd_actions, oatd_audit_events, oatd_assets`); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := postgresInsertEventsTx(ctx, tx, snap.Events); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := postgresInsertAlertsTx(ctx, tx, snap.Alerts); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := postgresInsertActionsTx(ctx, tx, snap.Actions); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := postgresInsertAuditsTx(ctx, tx, snap.Audits); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := postgresInsertAssetsTx(ctx, tx, snap.Assets); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func replaceFile(src string, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(src, dst)
}

func (s *Store) rebuildFingerprintsLocked() {
	s.fingerprints = make(map[string]struct{}, len(s.alerts))
	for _, alert := range s.alerts {
		if alert.Fingerprint != "" {
			s.fingerprints[alert.Fingerprint] = struct{}{}
		}
	}
}

func (s *Store) rebuildAssetsLocked() {
	s.assets = make(map[string]domain.Asset)
	for _, event := range s.events {
		s.upsertAssetLocked(event)
	}
	for _, alert := range s.alerts {
		s.raiseAssetRiskLocked(alert)
	}
}

func cloneAssets(assets map[string]domain.Asset) map[string]domain.Asset {
	cloned := make(map[string]domain.Asset, len(assets))
	for key, value := range assets {
		cloned[key] = value
	}
	return cloned
}

func (s *Store) enforceRetentionLocked() error {
	if s.retentionWindow <= 0 {
		return nil
	}

	cutoff := time.Now().UTC().Add(-s.retentionWindow)
	retained := s.retainedSnapshotLocked(cutoff)

	// Nothing aged out: skip the O(n) full rewrite (and, in Postgres mode, the
	// TRUNCATE + bulk re-INSERT of every table) that would otherwise run on every
	// single write even when no record is past the retention cutoff.
	if len(retained.Events) == len(s.events) &&
		len(retained.Alerts) == len(s.alerts) &&
		len(retained.Actions) == len(s.actions) &&
		len(retained.Audits) == len(s.audits) &&
		len(retained.Assets) == len(s.assets) {
		s.lastErr = ""
		return nil
	}

	s.events = append([]domain.Event(nil), retained.Events...)
	s.alerts = append([]domain.Alert(nil), retained.Alerts...)
	s.actions = append([]domain.ResponseAction(nil), retained.Actions...)
	s.audits = append([]domain.AuditEvent(nil), retained.Audits...)
	s.assets = cloneAssets(retained.Assets)
	s.rebuildFingerprintsLocked()

	if s.db != nil {
		if err := s.postgresRestoreSnapshotLocked(retained); err != nil {
			return err
		}
	}

	s.lastErr = ""
	return nil
}

func (s *Store) retainedSnapshotLocked(cutoff time.Time) Snapshot {
	retained := New()
	retained.mode = s.mode
	retained.path = s.path
	retained.db = s.db
	retained.schemaVersion = s.schemaVersion
	retained.events = filterEventsByCutoff(s.events, cutoff)
	retained.alerts = filterAlertsByCutoff(s.alerts, cutoff)
	retained.actions = filterActionsByCutoff(s.actions, cutoff)
	retained.audits = filterAuditsByCutoff(s.audits, cutoff)
	retained.rebuildAssetsLocked()
	retained.rebuildFingerprintsLocked()
	return retained.snapshotLocked()
}

func filterEventsByCutoff(events []domain.Event, cutoff time.Time) []domain.Event {
	filtered := make([]domain.Event, 0, len(events))
	for _, event := range events {
		if !event.Timestamp.IsZero() && event.Timestamp.Before(cutoff) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func filterAlertsByCutoff(alerts []domain.Alert, cutoff time.Time) []domain.Alert {
	filtered := make([]domain.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if !alert.CreatedAt.IsZero() && alert.CreatedAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, alert)
	}
	return filtered
}

func filterActionsByCutoff(actions []domain.ResponseAction, cutoff time.Time) []domain.ResponseAction {
	filtered := make([]domain.ResponseAction, 0, len(actions))
	for _, action := range actions {
		if !action.CreatedAt.IsZero() && action.CreatedAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, action)
	}
	return filtered
}

func filterAuditsByCutoff(audits []domain.AuditEvent, cutoff time.Time) []domain.AuditEvent {
	filtered := make([]domain.AuditEvent, 0, len(audits))
	for _, audit := range audits {
		if !audit.Timestamp.IsZero() && audit.Timestamp.Before(cutoff) {
			continue
		}
		filtered = append(filtered, audit)
	}
	return filtered
}

func redactPersistenceError(err string) string {
	err = strings.TrimSpace(err)
	if err == "" {
		return ""
	}
	lower := strings.ToLower(err)
	switch {
	case strings.Contains(lower, "postgres"):
		return "postgres persistence error"
	case strings.Contains(lower, ".json") || strings.Contains(lower, "snapshot"):
		return "snapshot persistence error"
	case strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted"):
		return "filesystem persistence error"
	default:
		return "persistence error"
	}
}
