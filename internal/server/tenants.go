package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/store"
)

type tenantIsolationMode string

const (
	tenantIsolationLogical  tenantIsolationMode = "logical"
	tenantIsolationPhysical tenantIsolationMode = "physical"
)

type tenantBackendConfig struct {
	Mode            string   `json:"mode"`
	PostgresDSN     string   `json:"postgres_dsn,omitempty"`
	DataPath        string   `json:"data_path,omitempty"`
	Admins          []string `json:"admins,omitempty"`
	PolicyProfile   string   `json:"policy_profile,omitempty"`
	RetentionWindow string   `json:"retention_window,omitempty"`
	SSOProfile      string   `json:"sso_profile,omitempty"`
	BackupTarget    string   `json:"backup_target,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
	Active          bool     `json:"active"`
	SchemaVersion   int      `json:"schema_version,omitempty"`
}

type tenantRegistryFile struct {
	Version int                            `json:"version"`
	SavedAt time.Time                      `json:"saved_at"`
	Tenants map[string]tenantBackendConfig `json:"tenants"`
}

type tenantRegistry struct {
	mu               sync.RWMutex
	path             string
	mode             tenantIsolationMode
	physicalMode     bool
	postgresTemplate string
	dataPathTemplate string
	baseStore        *store.Store
	backends         map[string]tenantBackendConfig
	stores           map[string]*store.Store
}

type tenantBackendView struct {
	Tenant          string   `json:"tenant"`
	Mode            string   `json:"mode"`
	PostgresDSN     string   `json:"postgres_dsn,omitempty"`
	DataPath        string   `json:"data_path,omitempty"`
	Admins          []string `json:"admins,omitempty"`
	PolicyProfile   string   `json:"policy_profile,omitempty"`
	RetentionWindow string   `json:"retention_window,omitempty"`
	SSOProfile      string   `json:"sso_profile,omitempty"`
	BackupTarget    string   `json:"backup_target,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	Active          bool     `json:"active"`
	SchemaVersion   int      `json:"schema_version,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

func newTenantRegistry(path string, mode string, postgresTemplate string, dataPathTemplate string, baseStore *store.Store) (*tenantRegistry, error) {
	reg := &tenantRegistry{
		path:             strings.TrimSpace(path),
		mode:             parseTenantIsolationMode(mode),
		physicalMode:     parseTenantIsolationMode(mode) == tenantIsolationPhysical,
		postgresTemplate: strings.TrimSpace(postgresTemplate),
		dataPathTemplate: strings.TrimSpace(dataPathTemplate),
		baseStore:        baseStore,
		backends:         make(map[string]tenantBackendConfig),
		stores:           make(map[string]*store.Store),
	}
	if err := reg.load(); err != nil {
		return nil, err
	}
	return reg, nil
}

func parseTenantIsolationMode(value string) tenantIsolationMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(tenantIsolationPhysical):
		return tenantIsolationPhysical
	default:
		return tenantIsolationLogical
	}
}

func (r *tenantRegistry) load() error {
	if r.path == "" {
		return nil
	}
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var file tenantRegistryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	if file.Tenants == nil {
		return nil
	}
	for tenant, cfg := range file.Tenants {
		r.backends[tenantOrDefault(tenant)] = cfg
	}
	return nil
}

func (r *tenantRegistry) persistLocked() error {
	if r.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return err
	}
	file := tenantRegistryFile{
		Version: 1,
		SavedAt: time.Now().UTC(),
		Tenants: make(map[string]tenantBackendConfig, len(r.backends)),
	}
	for tenant, cfg := range r.backends {
		file.Tenants[tenant] = cfg
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return replaceFile(tmp, r.path)
}

func (r *tenantRegistry) list() []tenantBackendConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenants := make([]tenantBackendConfig, 0, len(r.backends))
	for _, cfg := range r.backends {
		tenants = append(tenants, cfg)
	}
	return tenants
}

func (r *tenantRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.physicalMode {
		return 1
	}
	return len(r.backends)
}

func (r *tenantRegistry) listAsMaps() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.physicalMode {
		cfg := tenantBackendConfig{
			Mode:          r.baseStore.PersistenceMode(),
			Active:        true,
			SchemaVersion: r.baseStore.SchemaVersion(),
		}
		return []map[string]any{tenantConfigToMap("default", cfg)}
	}
	out := make([]map[string]any, 0, len(r.backends))
	for tenant, cfg := range r.backends {
		out = append(out, tenantConfigToMap(tenant, cfg))
	}
	return out
}

func (r *tenantRegistry) get(tenant string) (tenantBackendConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenant = tenantOrDefault(tenant)
	if !r.physicalMode && tenant == "default" {
		return tenantBackendConfig{
			Mode:          r.baseStore.PersistenceMode(),
			Active:        true,
			SchemaVersion: r.baseStore.SchemaVersion(),
		}, true
	}
	cfg, ok := r.backends[tenant]
	return cfg, ok
}

func (r *tenantRegistry) upsertTenant(tenant string, cfg tenantBackendConfig) (map[string]any, error) {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" && r.physicalMode {
		return nil, errors.New("default tenant is reserved")
	}
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))

	now := time.Now().UTC().Format(time.RFC3339Nano)
	r.mu.Lock()
	existing, hasExisting := r.backends[tenant]
	if hasExisting {
		cfg.CreatedAt = existing.CreatedAt
		if cfg.CreatedAt == "" {
			cfg.CreatedAt = now
		}
	} else {
		cfg.CreatedAt = now
	}
	cfg.UpdatedAt = now
	if cfg.Mode == "" {
		if hasExisting && existing.Mode != "" {
			cfg.Mode = existing.Mode
		} else if r.physicalMode {
			cfg.Mode = defaultTenantModeForBase(r.baseStore.PersistenceMode())
		} else {
			cfg.Mode = r.baseStore.PersistenceMode()
		}
	}
	if cfg.Admins == nil && hasExisting {
		cfg.Admins = append([]string(nil), existing.Admins...)
	}
	if cfg.Labels == nil && hasExisting {
		cfg.Labels = append([]string(nil), existing.Labels...)
	}
	if cfg.PolicyProfile == "" && hasExisting {
		cfg.PolicyProfile = existing.PolicyProfile
	}
	if cfg.RetentionWindow == "" && hasExisting {
		cfg.RetentionWindow = existing.RetentionWindow
	}
	if cfg.SSOProfile == "" && hasExisting {
		cfg.SSOProfile = existing.SSOProfile
	}
	if cfg.BackupTarget == "" && hasExisting {
		cfg.BackupTarget = existing.BackupTarget
	}
	if cfg.Notes == "" && hasExisting {
		cfg.Notes = existing.Notes
	}
	r.mu.Unlock()

	st, err := r.openBackend(cfg)
	if err != nil {
		return nil, err
	}
	if err := applyTenantSettings(st, cfg, r.physicalMode || normalizeTenantMode(cfg.Mode) != "logical"); err != nil {
		_ = st.Close()
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.stores[tenant]; old != nil && old != r.baseStore && old != st {
		_ = old.Close()
	}
	r.stores[tenant] = st
	cfg.Active = true
	cfg.SchemaVersion = st.SchemaVersion()
	r.backends[tenant] = cfg
	if err := r.persistLocked(); err != nil {
		return nil, err
	}
	return tenantConfigToMap(tenant, cfg), nil
}

func (r *tenantRegistry) deleteTenant(tenant string) (map[string]any, error) {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" && r.physicalMode {
		return nil, errors.New("default tenant is reserved")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg, ok := r.backends[tenant]
	if !ok && !r.physicalMode {
		cfg = tenantBackendConfig{
			Mode:          r.baseStore.PersistenceMode(),
			Active:        true,
			SchemaVersion: r.baseStore.SchemaVersion(),
		}
		delete(r.backends, tenant)
		return tenantConfigToMap(tenant, cfg), nil
	}
	if !ok {
		return nil, errors.New("tenant not found")
	}
	if st := r.stores[tenant]; st != nil && st != r.baseStore {
		_ = st.Close()
	}
	delete(r.stores, tenant)
	delete(r.backends, tenant)
	if err := r.persistLocked(); err != nil {
		return nil, err
	}
	cfg.Active = false
	return tenantConfigToMap(tenant, cfg), nil
}

func (r *tenantRegistry) ensureTenantStore(tenant string) (*store.Store, tenantBackendConfig, error) {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" && !r.physicalMode {
		return r.baseStore, tenantBackendConfig{
			Mode:          r.baseStore.PersistenceMode(),
			Active:        true,
			SchemaVersion: r.baseStore.SchemaVersion(),
		}, nil
	}

	r.mu.RLock()
	if st, ok := r.stores[tenant]; ok {
		cfg := r.backends[tenant]
		r.mu.RUnlock()
		return st, cfg, nil
	}
	cfg, ok := r.backends[tenant]
	r.mu.RUnlock()
	if !ok {
		if !r.physicalMode {
			return r.baseStore, tenantBackendConfig{
				Mode:          r.baseStore.PersistenceMode(),
				Active:        true,
				SchemaVersion: r.baseStore.SchemaVersion(),
			}, nil
		}
		var err error
		cfg, err = r.defaultBackendForTenant(tenant)
		if err != nil {
			return nil, tenantBackendConfig{}, err
		}
		if err := r.registerTenantBackend(tenant, cfg); err != nil {
			return nil, tenantBackendConfig{}, err
		}
	}

	st, err := r.openBackend(cfg)
	if err != nil {
		return nil, cfg, err
	}
	if err := applyTenantSettings(st, cfg, r.physicalMode || normalizeTenantMode(cfg.Mode) != "logical"); err != nil {
		return nil, cfg, err
	}
	r.mu.Lock()
	r.stores[tenant] = st
	cfg.Active = true
	cfg.SchemaVersion = st.SchemaVersion()
	r.backends[tenant] = cfg
	_ = r.persistLocked()
	r.mu.Unlock()
	return st, cfg, nil
}

func (r *tenantRegistry) registerTenantBackend(tenant string, cfg tenantBackendConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenant = tenantOrDefault(tenant)
	if tenant == "default" {
		return errors.New("default tenant is reserved")
	}
	cfg.Active = false
	if cfg.CreatedAt == "" {
		cfg.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.backends[tenant] = cfg
	return r.persistLocked()
}

func (r *tenantRegistry) registerTenant(tenant string, mode string, postgresDSN string, dataPath string, admins []string, policyProfile string, retentionWindow string, ssoProfile string, backupTarget string, labels []string, notes string) (map[string]any, error) {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" {
		return nil, errors.New("default tenant is reserved")
	}
	cfg := tenantBackendConfig{
		Mode:            normalizeTenantMode(mode),
		Admins:          normalizeTenantValues(admins),
		PolicyProfile:   strings.TrimSpace(policyProfile),
		RetentionWindow: strings.TrimSpace(retentionWindow),
		SSOProfile:      strings.TrimSpace(ssoProfile),
		BackupTarget:    strings.TrimSpace(backupTarget),
		Labels:          normalizeTenantValues(labels),
		Notes:           strings.TrimSpace(notes),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	switch cfg.Mode {
	case "":
		if r.physicalMode {
			cfg.Mode = defaultTenantModeForBase(r.baseStore.PersistenceMode())
			break
		}
		cfg.Mode = "logical"
	case "logical":
		cfg.Mode = "logical"
	case "postgres":
		cfg.PostgresDSN = strings.TrimSpace(postgresDSN)
		if cfg.PostgresDSN == "" {
			if !r.physicalMode {
				return nil, errors.New("postgres dsn is required for physical tenant provisioning")
			}
			template, err := r.defaultBackendForTenant(tenant)
			if err != nil {
				return nil, err
			}
			cfg.PostgresDSN = template.PostgresDSN
		}
	case "file":
		cfg.DataPath = strings.TrimSpace(dataPath)
		if cfg.DataPath == "" {
			if !r.physicalMode {
				return nil, errors.New("data path is required for physical tenant provisioning")
			}
			template, err := r.defaultBackendForTenant(tenant)
			if err != nil {
				return nil, err
			}
			cfg.DataPath = template.DataPath
		}
	default:
		return nil, fmt.Errorf("unsupported tenant mode %q", cfg.Mode)
	}
	return r.upsertTenant(tenant, cfg)
}

func (r *tenantRegistry) updateTenant(tenant string, mode string, postgresDSN string, dataPath string, admins []string, policyProfile string, retentionWindow string, ssoProfile string, backupTarget string, labels []string, notes string) (map[string]any, error) {
	tenant = tenantOrDefault(tenant)
	existing, ok := r.get(tenant)
	if !ok {
		if tenant == "default" {
			existing = tenantBackendConfig{Mode: r.baseStore.PersistenceMode()}
		}
	}
	cfg := existing
	if mode = strings.TrimSpace(mode); mode != "" {
		cfg.Mode = normalizeTenantMode(mode)
	}
	if postgresDSN = strings.TrimSpace(postgresDSN); postgresDSN != "" {
		cfg.PostgresDSN = postgresDSN
	}
	if dataPath = strings.TrimSpace(dataPath); dataPath != "" {
		cfg.DataPath = dataPath
	}
	if len(admins) > 0 {
		cfg.Admins = normalizeTenantValues(admins)
	}
	if policyProfile = strings.TrimSpace(policyProfile); policyProfile != "" {
		cfg.PolicyProfile = policyProfile
	}
	if retentionWindow = strings.TrimSpace(retentionWindow); retentionWindow != "" {
		cfg.RetentionWindow = retentionWindow
	}
	if ssoProfile = strings.TrimSpace(ssoProfile); ssoProfile != "" {
		cfg.SSOProfile = ssoProfile
	}
	if backupTarget = strings.TrimSpace(backupTarget); backupTarget != "" {
		cfg.BackupTarget = backupTarget
	}
	if len(labels) > 0 {
		cfg.Labels = normalizeTenantValues(labels)
	}
	if notes = strings.TrimSpace(notes); notes != "" {
		cfg.Notes = notes
	}
	return r.upsertTenant(tenant, cfg)
}

func (r *tenantRegistry) openBackend(cfg tenantBackendConfig) (*store.Store, error) {
	switch normalizeTenantMode(cfg.Mode) {
	case "", "logical":
		return r.baseStore, nil
	case "postgres":
		if strings.TrimSpace(cfg.PostgresDSN) == "" {
			return nil, errors.New("tenant postgres dsn is required")
		}
		return store.NewWithPostgres(cfg.PostgresDSN)
	case "file":
		if strings.TrimSpace(cfg.DataPath) == "" {
			return nil, errors.New("tenant data path is required")
		}
		return store.NewWithPath(cfg.DataPath)
	default:
		return nil, fmt.Errorf("unsupported tenant backend mode %q", cfg.Mode)
	}
}

func (r *tenantRegistry) defaultBackendForTenant(tenant string) (tenantBackendConfig, error) {
	slug := sanitizeTenantSlug(tenant)
	switch r.baseStore.PersistenceMode() {
	case "postgres":
		if r.postgresTemplate == "" {
			return tenantBackendConfig{}, errors.New("tenant physical isolation requires --tenant-postgres-dsn-template")
		}
		return tenantBackendConfig{
			Mode:        "postgres",
			PostgresDSN: strings.ReplaceAll(r.postgresTemplate, "{tenant}", slug),
			CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
			UpdatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		}, nil
	case "file":
		if r.dataPathTemplate == "" {
			return tenantBackendConfig{}, errors.New("tenant physical isolation requires --tenant-data-path-template")
		}
		return tenantBackendConfig{
			Mode:      "file",
			DataPath:  strings.ReplaceAll(r.dataPathTemplate, "{tenant}", slug),
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, nil
	default:
		return tenantBackendConfig{}, fmt.Errorf("unsupported base backend %q", r.baseStore.PersistenceMode())
	}
}

func tenantConfigToMap(tenant string, cfg tenantBackendConfig) map[string]any {
	return map[string]any{
		"tenant":           tenant,
		"mode":             cfg.Mode,
		"postgres_dsn":     redactTenantDSN(cfg.PostgresDSN),
		"data_path":        cfg.DataPath,
		"admins":           append([]string(nil), cfg.Admins...),
		"policy_profile":   cfg.PolicyProfile,
		"retention_window": cfg.RetentionWindow,
		"sso_profile":      cfg.SSOProfile,
		"backup_target":    cfg.BackupTarget,
		"labels":           append([]string(nil), cfg.Labels...),
		"notes":            cfg.Notes,
		"active":           cfg.Active,
		"schema_version":   cfg.SchemaVersion,
		"created_at":       cfg.CreatedAt,
		"updated_at":       cfg.UpdatedAt,
	}
}

func applyTenantSettings(st *store.Store, cfg tenantBackendConfig, applyRetention bool) error {
	if st == nil {
		return nil
	}
	if !applyRetention {
		return nil
	}
	duration, ok, err := parseFlexibleDurationValue(cfg.RetentionWindow)
	if err != nil {
		return err
	}
	if ok {
		if err := st.SetRetention(duration); err != nil {
			return err
		}
	}
	return nil
}

func normalizeTenantMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "logical":
		return "logical"
	case "postgres", "file":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeTenantValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func defaultTenantModeForBase(base string) string {
	switch strings.ToLower(strings.TrimSpace(base)) {
	case "postgres":
		return "postgres"
	case "file":
		return "file"
	default:
		return "logical"
	}
}

func parseFlexibleDurationValue(value string) (time.Duration, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, true, nil
	}
	for _, suffix := range []struct {
		suffix string
		scale  time.Duration
	}{
		{suffix: "w", scale: 7 * 24 * time.Hour},
		{suffix: "d", scale: 24 * time.Hour},
	} {
		if !strings.HasSuffix(value, suffix.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(value, suffix.suffix))
		amount, err := strconv.ParseFloat(number, 64)
		if err != nil {
			return 0, false, err
		}
		return time.Duration(amount * float64(suffix.scale)), true, nil
	}
	return 0, false, fmt.Errorf("invalid duration %q", value)
}

func sanitizeTenantSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "default"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	slug := strings.Trim(builder.String(), "-_.")
	if slug == "" {
		return "tenant"
	}
	return slug
}

func redactTenantDSN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "@"); idx > -1 {
		prefix := value[:idx]
		if colon := strings.LastIndex(prefix, ":"); colon > -1 {
			return prefix[:colon+1] + "****" + value[idx:]
		}
	}
	return value
}

func replaceFile(src string, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, input, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}
