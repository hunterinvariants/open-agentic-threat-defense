package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const postgresTimeout = 10 * time.Second
const loginBackoffCap = 1 * time.Minute

func NewWithPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := New()
	s.db = db
	s.mode = "postgres"
	s.path = redactDSN(dsn)
	if err := s.postgresMigrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.postgresLoad(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) postgresMigrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `SELECT pg_advisory_lock(72743001)`); err != nil {
		return err
	}
	defer s.db.ExecContext(context.Background(), `SELECT pg_advisory_unlock(72743001)`)

	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS oatd_schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`); err != nil {
		return err
	}

	applied, err := s.postgresAppliedMigrations(ctx)
	if err != nil {
		return err
	}
	for _, migration := range postgresMigrations {
		if applied[migration.Version] {
			continue
		}
		if err := s.applyPostgresMigration(ctx, migration); err != nil {
			return err
		}
		applied[migration.Version] = true
	}

	version, err := s.postgresCurrentSchemaVersion(ctx)
	if err != nil {
		return err
	}
	s.schemaVersion = version
	return nil
}

func (s *Store) postgresAppliedMigrations(ctx context.Context) (map[int]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM oatd_schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func (s *Store) applyPostgresMigration(ctx context.Context, migration postgresMigration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("apply postgres migration %d %s: %w", migration.Version, migration.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_schema_migrations (version, name)
VALUES ($1, $2)
ON CONFLICT (version) DO NOTHING`, migration.Version, migration.Name); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Store) postgresCurrentSchemaVersion(ctx context.Context) (int, error) {
	var version sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT max(version) FROM oatd_schema_migrations`).Scan(&version); err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

type postgresMigration struct {
	Version int
	Name    string
	SQL     string
}

var postgresMigrations = []postgresMigration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQL: `
CREATE TABLE IF NOT EXISTS oatd_events (
  id TEXT PRIMARY KEY,
  occurred_at TIMESTAMPTZ,
  asset_id TEXT,
  kind TEXT,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oatd_events_occurred_at ON oatd_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_oatd_events_asset_id ON oatd_events (asset_id);

CREATE TABLE IF NOT EXISTS oatd_alerts (
  id TEXT PRIMARY KEY,
  fingerprint TEXT UNIQUE,
  created_at TIMESTAMPTZ,
  asset_id TEXT,
  severity TEXT,
  status TEXT,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oatd_alerts_created_at ON oatd_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_oatd_alerts_asset_id ON oatd_alerts (asset_id);
CREATE INDEX IF NOT EXISTS idx_oatd_alerts_status ON oatd_alerts (status);

CREATE TABLE IF NOT EXISTS oatd_actions (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ,
  asset_id TEXT,
  approval_status TEXT,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oatd_actions_created_at ON oatd_actions (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_oatd_actions_asset_id ON oatd_actions (asset_id);

CREATE TABLE IF NOT EXISTS oatd_assets (
  id TEXT PRIMARY KEY,
  last_seen TIMESTAMPTZ,
  risk_score INTEGER,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS oatd_audit_events (
  id TEXT PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  outcome TEXT,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oatd_audit_events_occurred_at ON oatd_audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_oatd_audit_events_actor ON oatd_audit_events (actor);
CREATE INDEX IF NOT EXISTS idx_oatd_audit_events_action ON oatd_audit_events (action);`,
	},
	{
		Version: 2,
		Name:    "audit_chain_state_and_login_attempts",
		SQL: `
CREATE TABLE IF NOT EXISTS oatd_audit_chain_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  head_hash TEXT NOT NULL DEFAULT '',
  chain_index INTEGER NOT NULL DEFAULT 0,
  valid BOOLEAN NOT NULL DEFAULT TRUE,
  anchor_hmac TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO oatd_audit_chain_state (id, head_hash, chain_index, valid)
VALUES (1, '', 0, TRUE)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS oatd_login_attempts (
  key TEXT PRIMARY KEY,
  failures INTEGER NOT NULL DEFAULT 0,
  blocked_until TIMESTAMPTZ,
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oatd_login_attempts_blocked_until ON oatd_login_attempts (blocked_until DESC);
CREATE INDEX IF NOT EXISTS idx_oatd_login_attempts_last_seen ON oatd_login_attempts (last_seen DESC);`,
	},
	{
		Version: 3,
		Name:    "audit_chain_anchor_hmac",
		SQL: `
ALTER TABLE oatd_audit_chain_state
ADD COLUMN IF NOT EXISTS anchor_hmac TEXT NOT NULL DEFAULT '';`,
	},
}

func (s *Store) postgresLoad(ctx context.Context) error {
	if err := s.postgresLoadEvents(ctx); err != nil {
		return err
	}
	if err := s.postgresLoadAlerts(ctx); err != nil {
		return err
	}
	if err := s.postgresLoadActions(ctx); err != nil {
		return err
	}
	if err := s.postgresLoadAssets(ctx); err != nil {
		return err
	}
	if err := s.postgresLoadAudits(ctx); err != nil {
		return err
	}
	s.rebuildFingerprintsLocked()
	if len(s.assets) == 0 {
		s.rebuildAssetsLocked()
	}
	s.rebuildAuditChainLocked()
	if err := s.postgresSyncAuditChainState(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) postgresLoadEvents(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM oatd_events ORDER BY occurred_at ASC NULLS LAST, id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var event domain.Event
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		s.events = append(s.events, event)
	}
	return rows.Err()
}

func (s *Store) postgresLoadAlerts(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM oatd_alerts ORDER BY created_at ASC NULLS LAST, id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var alert domain.Alert
		if err := json.Unmarshal(data, &alert); err != nil {
			return err
		}
		s.alerts = append(s.alerts, alert)
	}
	return rows.Err()
}

func (s *Store) postgresLoadActions(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM oatd_actions ORDER BY created_at ASC NULLS LAST, id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var action domain.ResponseAction
		if err := json.Unmarshal(data, &action); err != nil {
			return err
		}
		s.actions = append(s.actions, action)
	}
	return rows.Err()
}

func (s *Store) postgresLoadAssets(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM oatd_assets`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var asset domain.Asset
		if err := json.Unmarshal(data, &asset); err != nil {
			return err
		}
		if asset.ID != "" {
			s.assets[asset.ID] = asset
		}
	}
	return rows.Err()
}

func (s *Store) postgresLoadAudits(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM oatd_audit_events ORDER BY occurred_at ASC, id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		var event domain.AuditEvent
		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		s.audits = append(s.audits, event)
	}
	return rows.Err()
}

func (s *Store) postgresSyncAuditChainState(ctx context.Context) error {
	if s.db == nil {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO oatd_audit_chain_state (id, head_hash, chain_index, valid, anchor_hmac, updated_at)
VALUES (1, $1, $2, $3, $4, now())
ON CONFLICT (id) DO UPDATE SET
  head_hash = EXCLUDED.head_hash,
  chain_index = EXCLUDED.chain_index,
  valid = EXCLUDED.valid,
  anchor_hmac = EXCLUDED.anchor_hmac,
  updated_at = EXCLUDED.updated_at`,
		s.auditChainHead, len(s.audits), s.auditChainValid, s.auditChainAnchor); err != nil {
		return err
	}
	return nil
}

func (s *Store) postgresAddAuditLocked(event domain.AuditEvent) (domain.AuditEvent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_lock(72743001)`); err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}
	defer tx.ExecContext(context.Background(), `SELECT pg_advisory_unlock(72743001)`)

	if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_audit_chain_state (id, head_hash, chain_index, valid, anchor_hmac, updated_at)
VALUES (1, '', 0, TRUE, '', now())
ON CONFLICT (id) DO NOTHING`); err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}

	var headHash string
	var chainIndex int
	if err := tx.QueryRowContext(ctx, `SELECT head_hash, chain_index FROM oatd_audit_chain_state WHERE id = 1 FOR UPDATE`).Scan(&headHash, &chainIndex); err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}

	event.ChainIndex = chainIndex + 1
	event.PrevHash = headHash
	event.Hash = auditEventHash(event, event.PrevHash)
	data, err := json.Marshal(event)
	if err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_audit_events (id, occurred_at, actor, action, resource_type, resource_id, outcome, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
  occurred_at = EXCLUDED.occurred_at,
  actor = EXCLUDED.actor,
  action = EXCLUDED.action,
  resource_type = EXCLUDED.resource_type,
  resource_id = EXCLUDED.resource_id,
  outcome = EXCLUDED.outcome,
  data = EXCLUDED.data`,
		event.ID, event.Timestamp, event.Actor, event.Action, event.ResourceType, event.ResourceID, event.Outcome, data); err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE oatd_audit_chain_state
SET head_hash = $1, chain_index = $2, valid = TRUE, anchor_hmac = $3, updated_at = now()
WHERE id = 1`, event.Hash, event.ChainIndex, auditChainAnchorValue(event.Hash, event.ChainIndex, true)); err != nil {
		_ = tx.Rollback()
		return domain.AuditEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.AuditEvent{}, err
	}
	s.auditChainHead = event.Hash
	s.auditChainValid = true
	s.auditChainAnchor = auditChainAnchorValue(event.Hash, event.ChainIndex, true)
	return event, nil
}

func (s *Store) postgresAuditChainSnapshot() AuditChainSnapshot {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()

	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return AuditChainSnapshot{}
	}

	snap := AuditChainSnapshot{}
	var headHash sql.NullString
	var chainIndex sql.NullInt64
	var valid sql.NullBool
	var anchor sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT head_hash, chain_index, valid, anchor_hmac FROM oatd_audit_chain_state WHERE id = 1`).Scan(&headHash, &chainIndex, &valid, &anchor); err != nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.auditChainSnapshotLocked()
	}
	if headHash.Valid {
		snap.Head = headHash.String
	}
	if chainIndex.Valid {
		snap.Linked = int(chainIndex.Int64)
	}
	if valid.Valid {
		snap.Valid = valid.Bool
	}
	if anchor.Valid {
		snap.Anchor = anchor.String
		snap.Anchored = strings.TrimSpace(anchor.String) != ""
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM oatd_audit_events`).Scan(&snap.Total); err != nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.auditChainSnapshotLocked()
	}
	if snap.Head == "" {
		snap.Valid = snap.Total == 0
		snap.Anchored = false
		return snap
	}
	expectedAnchor := auditChainAnchorValue(snap.Head, snap.Linked, snap.Valid)
	if expectedAnchor != "" {
		snap.Anchored = true
		if snap.Anchor != "" && snap.Anchor != expectedAnchor {
			snap.Valid = false
		}
		snap.Anchor = expectedAnchor
	}
	var (
		id   string
		ts   time.Time
		data []byte
	)
	if err := db.QueryRowContext(ctx, `SELECT id, occurred_at, data FROM oatd_audit_events WHERE data->>'hash' = $1 LIMIT 1`, snap.Head).Scan(&id, &ts, &data); err != nil {
		snap.Valid = false
		return snap
	}
	snap.LastAuditID = id
	snap.LastTimestamp = ts
	var event domain.AuditEvent
	if err := json.Unmarshal(data, &event); err == nil {
		snap.Previous = event.PrevHash
	}
	return snap
}

func (s *Store) postgresLoginRetryAfter(key string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, nil
	}
	var blockedUntil sql.NullTime
	if err := s.db.QueryRowContext(ctx, `SELECT blocked_until FROM oatd_login_attempts WHERE key = $1`, key).Scan(&blockedUntil); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	if !blockedUntil.Valid {
		return 0, nil
	}
	wait := time.Until(blockedUntil.Time)
	if wait < 0 {
		return 0, nil
	}
	return wait, nil
}

func (s *Store) postgresRecordLoginAttempt(key string, success bool) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	key = strings.TrimSpace(key)
	if key == "" {
		return 0, nil
	}
	now := time.Now().UTC()
	if success {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM oatd_login_attempts WHERE key = $1`, key); err != nil {
			return 0, err
		}
		return 0, nil
	}
	var failures int
	err := s.db.QueryRowContext(ctx, `SELECT failures FROM oatd_login_attempts WHERE key = $1`, key).Scan(&failures)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if failures < 0 {
		failures = 0
	}
	failures++
	if failures > 8 {
		failures = 8
	}
	delay := time.Second << (failures - 1)
	if delay > loginBackoffCap {
		delay = loginBackoffCap
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO oatd_login_attempts (key, failures, blocked_until, last_seen)
VALUES ($1, $2, $3, $4)
ON CONFLICT (key) DO UPDATE SET
  failures = EXCLUDED.failures,
  blocked_until = EXCLUDED.blocked_until,
  last_seen = EXCLUDED.last_seen`,
		key, failures, now.Add(delay), now)
	return delay, err
}

func (s *Store) postgresPersistEventLocked(event domain.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO oatd_events (id, occurred_at, asset_id, kind, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
  occurred_at = EXCLUDED.occurred_at,
  asset_id = EXCLUDED.asset_id,
  kind = EXCLUDED.kind,
  data = EXCLUDED.data`,
		event.ID, nullableTime(event.Timestamp), event.AssetID, string(event.Kind), data); err != nil {
		return err
	}
	return s.postgresPersistAssetsLocked(ctx)
}

func postgresInsertEventsTx(ctx context.Context, tx *sql.Tx, events []domain.Event) error {
	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_events (id, occurred_at, asset_id, kind, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
  occurred_at = EXCLUDED.occurred_at,
  asset_id = EXCLUDED.asset_id,
  kind = EXCLUDED.kind,
  data = EXCLUDED.data`,
			event.ID, nullableTime(event.Timestamp), event.AssetID, string(event.Kind), data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) postgresPersistAlertsLocked(alerts []domain.Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	for _, alert := range alerts {
		data, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO oatd_alerts (id, fingerprint, created_at, asset_id, severity, status, data)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
  fingerprint = EXCLUDED.fingerprint,
  created_at = EXCLUDED.created_at,
  asset_id = EXCLUDED.asset_id,
  severity = EXCLUDED.severity,
  status = EXCLUDED.status,
  data = EXCLUDED.data`,
			alert.ID, nullEmpty(alert.Fingerprint), nullableTime(alert.CreatedAt), alert.AssetID, string(alert.Severity), string(alert.Status), data); err != nil {
			return err
		}
	}
	return s.postgresPersistAssetsLocked(ctx)
}

func postgresInsertAlertsTx(ctx context.Context, tx *sql.Tx, alerts []domain.Alert) error {
	for _, alert := range alerts {
		data, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_alerts (id, fingerprint, created_at, asset_id, severity, status, data)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
  fingerprint = EXCLUDED.fingerprint,
  created_at = EXCLUDED.created_at,
  asset_id = EXCLUDED.asset_id,
  severity = EXCLUDED.severity,
  status = EXCLUDED.status,
  data = EXCLUDED.data`,
			alert.ID, nullEmpty(alert.Fingerprint), nullableTime(alert.CreatedAt), alert.AssetID, string(alert.Severity), string(alert.Status), data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) postgresPersistActionsLocked(actions []domain.ResponseAction) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	for _, action := range actions {
		data, err := json.Marshal(action)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO oatd_actions (id, created_at, asset_id, approval_status, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
  created_at = EXCLUDED.created_at,
  asset_id = EXCLUDED.asset_id,
  approval_status = EXCLUDED.approval_status,
  data = EXCLUDED.data`,
			action.ID, nullableTime(action.CreatedAt), action.AssetID, action.ApprovalStatus, data); err != nil {
			return err
		}
	}
	return nil
}

func postgresInsertActionsTx(ctx context.Context, tx *sql.Tx, actions []domain.ResponseAction) error {
	for _, action := range actions {
		data, err := json.Marshal(action)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_actions (id, created_at, asset_id, approval_status, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (id) DO UPDATE SET
  created_at = EXCLUDED.created_at,
  asset_id = EXCLUDED.asset_id,
  approval_status = EXCLUDED.approval_status,
  data = EXCLUDED.data`,
			action.ID, nullableTime(action.CreatedAt), action.AssetID, action.ApprovalStatus, data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) postgresPersistAuditLocked(event domain.AuditEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), postgresTimeout)
	defer cancel()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO oatd_audit_events (id, occurred_at, actor, action, resource_type, resource_id, outcome, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
  occurred_at = EXCLUDED.occurred_at,
  actor = EXCLUDED.actor,
  action = EXCLUDED.action,
  resource_type = EXCLUDED.resource_type,
  resource_id = EXCLUDED.resource_id,
  outcome = EXCLUDED.outcome,
  data = EXCLUDED.data`,
		event.ID, event.Timestamp, event.Actor, event.Action, event.ResourceType, event.ResourceID, event.Outcome, data)
	return err
}

func postgresInsertAuditsTx(ctx context.Context, tx *sql.Tx, audits []domain.AuditEvent) error {
	for _, event := range audits {
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_audit_events (id, occurred_at, actor, action, resource_type, resource_id, outcome, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET
  occurred_at = EXCLUDED.occurred_at,
  actor = EXCLUDED.actor,
  action = EXCLUDED.action,
  resource_type = EXCLUDED.resource_type,
  resource_id = EXCLUDED.resource_id,
  outcome = EXCLUDED.outcome,
  data = EXCLUDED.data`,
			event.ID, event.Timestamp, event.Actor, event.Action, event.ResourceType, event.ResourceID, event.Outcome, data); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) postgresPersistAssetsLocked(ctx context.Context) error {
	for _, asset := range s.assets {
		data, err := json.Marshal(asset)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `
INSERT INTO oatd_assets (id, last_seen, risk_score, data)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
  last_seen = EXCLUDED.last_seen,
  risk_score = EXCLUDED.risk_score,
  data = EXCLUDED.data`,
			asset.ID, nullableTime(asset.LastSeen), asset.RiskScore, data); err != nil {
			return err
		}
	}
	return nil
}

func postgresInsertAssetsTx(ctx context.Context, tx *sql.Tx, assets map[string]domain.Asset) error {
	for _, asset := range assets {
		data, err := json.Marshal(asset)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO oatd_assets (id, last_seen, risk_score, data)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO UPDATE SET
  last_seen = EXCLUDED.last_seen,
  risk_score = EXCLUDED.risk_score,
  data = EXCLUDED.data`,
			asset.ID, nullableTime(asset.LastSeen), asset.RiskScore, data); err != nil {
			return err
		}
	}
	return nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func redactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	return "postgres"
}
