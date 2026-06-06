package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const snapshotVersion = 1

type snapshot struct {
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

	var snap snapshot
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
	return s, nil
}

func (s *Store) persistLocked() error {
	if s.path == "" || s.mode == "postgres" {
		s.lastErr = ""
		return nil
	}

	snap := snapshot{
		Version: snapshotVersion,
		SavedAt: time.Now().UTC(),
		Events:  append([]domain.Event(nil), s.events...),
		Alerts:  append([]domain.Alert(nil), s.alerts...),
		Actions: append([]domain.ResponseAction(nil), s.actions...),
		Audits:  append([]domain.AuditEvent(nil), s.audits...),
		Assets:  cloneAssets(s.assets),
	}

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
