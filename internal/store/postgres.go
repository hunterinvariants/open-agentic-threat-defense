package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const postgresTimeout = 10 * time.Second

func NewWithPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
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
