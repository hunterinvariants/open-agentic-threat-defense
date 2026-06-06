package store

import (
	"database/sql"
	"sort"
	"sync"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Store struct {
	mu           sync.RWMutex
	db           *sql.DB
	mode         string
	events       []domain.Event
	alerts       []domain.Alert
	actions      []domain.ResponseAction
	audits       []domain.AuditEvent
	assets       map[string]domain.Asset
	fingerprints map[string]struct{}
	path         string
	lastErr      string
}

func New() *Store {
	return &Store{
		mode:         "memory",
		assets:       make(map[string]domain.Asset),
		fingerprints: make(map[string]struct{}),
	}
}

func (s *Store) AddEvent(event domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	s.upsertAssetLocked(event)
	if err := s.persistEventLocked(event); err != nil {
		s.lastErr = err.Error()
		return err
	}
	return s.persistLocked()
}

func (s *Store) ListEvents() []domain.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := make([]domain.Event, len(s.events))
	copy(events, s.events)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	return events
}

func (s *Store) AddAlerts(alerts []domain.Alert) ([]domain.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	added := make([]domain.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if alert.Fingerprint != "" {
			if _, ok := s.fingerprints[alert.Fingerprint]; ok {
				continue
			}
			s.fingerprints[alert.Fingerprint] = struct{}{}
		}
		s.alerts = append(s.alerts, alert)
		added = append(added, alert)
		s.raiseAssetRiskLocked(alert)
	}
	if len(added) == 0 {
		return added, nil
	}
	if err := s.persistAlertsLocked(added); err != nil {
		s.lastErr = err.Error()
		return nil, err
	}
	return added, s.persistLocked()
}

func (s *Store) ListAlerts() []domain.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alerts := make([]domain.Alert, len(s.alerts))
	copy(alerts, s.alerts)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].CreatedAt.After(alerts[j].CreatedAt)
	})
	return alerts
}

func (s *Store) GetAlert(id string) (domain.Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, alert := range s.alerts {
		if alert.ID == id {
			return alert, true
		}
	}
	return domain.Alert{}, false
}

func (s *Store) AddActions(actions []domain.ResponseAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.actions = append(s.actions, actions...)
	if err := s.persistActionsLocked(actions); err != nil {
		s.lastErr = err.Error()
		return err
	}
	return s.persistLocked()
}

func (s *Store) ApproveAction(id string, approvedBy string, approvedAt time.Time) (domain.ResponseAction, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.actions {
		if s.actions[i].ID != id {
			continue
		}
		s.actions[i].ApprovalStatus = "approved"
		s.actions[i].ApprovedBy = approvedBy
		s.actions[i].ApprovedAt = &approvedAt
		if err := s.persistActionsLocked([]domain.ResponseAction{s.actions[i]}); err != nil {
			s.lastErr = err.Error()
			return domain.ResponseAction{}, true, err
		}
		if err := s.persistLocked(); err != nil {
			return domain.ResponseAction{}, true, err
		}
		return s.actions[i], true, nil
	}
	return domain.ResponseAction{}, false, nil
}

func (s *Store) ListActions() []domain.ResponseAction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	actions := make([]domain.ResponseAction, len(s.actions))
	copy(actions, s.actions)
	sort.Slice(actions, func(i, j int) bool {
		return actions[i].CreatedAt.After(actions[j].CreatedAt)
	})
	return actions
}

func (s *Store) AddAudit(event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.audits = append(s.audits, event)
	if err := s.persistAuditLocked(event); err != nil {
		s.lastErr = err.Error()
		return err
	}
	return s.persistLocked()
}

func (s *Store) ListAudits() []domain.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	audits := make([]domain.AuditEvent, len(s.audits))
	copy(audits, s.audits)
	sort.Slice(audits, func(i, j int) bool {
		return audits[i].Timestamp.After(audits[j].Timestamp)
	})
	return audits
}

func (s *Store) ListAssets() []domain.Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assets := make([]domain.Asset, 0, len(s.assets))
	for _, asset := range s.assets {
		assets = append(assets, asset)
	}
	sort.Slice(assets, func(i, j int) bool {
		if assets[i].RiskScore == assets[j].RiskScore {
			return assets[i].LastSeen.After(assets[j].LastSeen)
		}
		return assets[i].RiskScore > assets[j].RiskScore
	})
	return assets
}

func (s *Store) Counts() (events int, alerts int, assets int, actions int, audits int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.events), len(s.alerts), len(s.assets), len(s.actions), len(s.audits)
}

func (s *Store) PersistencePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.path
}

func (s *Store) PersistenceMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.mode
}

func (s *Store) LastPersistenceError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.lastErr
}

func (s *Store) upsertAssetLocked(event domain.Event) {
	if event.AssetID == "" {
		return
	}

	asset := s.assets[event.AssetID]
	asset.ID = event.AssetID
	if event.Hostname != "" {
		asset.Hostname = event.Hostname
	}
	if asset.Hostname == "" {
		asset.Hostname = event.AssetID
	}
	if event.SourceIP != "" && !contains(asset.IPs, event.SourceIP) {
		asset.IPs = append(asset.IPs, event.SourceIP)
	}
	if event.ToolName != "" && event.Kind == domain.EventAgentToolCall && !contains(asset.AgentSurface, event.ToolName) {
		asset.AgentSurface = append(asset.AgentSurface, event.ToolName)
	}
	asset.LastSeen = latest(asset.LastSeen, event.Timestamp)
	asset.Labels = merge(asset.Labels, event.Labels)
	if asset.Metadata == nil {
		asset.Metadata = make(map[string]string)
	}
	for k, v := range event.Metadata {
		asset.Metadata[k] = v
	}
	s.assets[event.AssetID] = asset
}

func (s *Store) raiseAssetRiskLocked(alert domain.Alert) {
	if alert.AssetID == "" {
		return
	}

	asset := s.assets[alert.AssetID]
	asset.ID = alert.AssetID
	if asset.Hostname == "" {
		asset.Hostname = alert.AssetID
	}
	asset.RiskScore += alert.Severity.Rank() * 10
	if asset.LastSeen.IsZero() {
		asset.LastSeen = alert.CreatedAt
	}
	s.assets[alert.AssetID] = asset
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func merge(existing []string, incoming []string) []string {
	merged := append([]string(nil), existing...)
	for _, value := range incoming {
		if !contains(merged, value) {
			merged = append(merged, value)
		}
	}
	return merged
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
