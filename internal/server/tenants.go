package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Mode          string `json:"mode"`
	PostgresDSN   string `json:"postgres_dsn,omitempty"`
	DataPath      string `json:"data_path,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
	Active        bool   `json:"active"`
	SchemaVersion int    `json:"schema_version,omitempty"`
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
	Tenant        string `json:"tenant"`
	Mode          string `json:"mode"`
	PostgresDSN   string `json:"postgres_dsn,omitempty"`
	DataPath      string `json:"data_path,omitempty"`
	Active        bool   `json:"active"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
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
	out := make([]map[string]any, 0, len(r.backends))
	for tenant, cfg := range r.backends {
		out = append(out, map[string]any{
			"tenant":         tenant,
			"mode":           cfg.Mode,
			"postgres_dsn":   redactTenantDSN(cfg.PostgresDSN),
			"data_path":      cfg.DataPath,
			"active":         cfg.Active,
			"schema_version": cfg.SchemaVersion,
			"created_at":     cfg.CreatedAt,
			"updated_at":     cfg.UpdatedAt,
		})
	}
	return out
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

func (r *tenantRegistry) registerTenant(tenant string, mode string, postgresDSN string, dataPath string) (map[string]any, error) {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" {
		return nil, errors.New("default tenant is reserved")
	}
	cfg := tenantBackendConfig{
		Mode:      strings.TrimSpace(mode),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "", "logical":
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
	if err := r.registerTenantBackend(tenant, cfg); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.openBackend(cfg)
	if err != nil {
		return nil, err
	}
	r.stores[tenant] = st
	cfg.Active = true
	cfg.SchemaVersion = st.SchemaVersion()
	r.backends[tenant] = cfg
	if err := r.persistLocked(); err != nil {
		return nil, err
	}
	return map[string]any{
		"tenant":         tenant,
		"mode":           cfg.Mode,
		"postgres_dsn":   redactTenantDSN(cfg.PostgresDSN),
		"data_path":      cfg.DataPath,
		"active":         cfg.Active,
		"schema_version": cfg.SchemaVersion,
		"created_at":     cfg.CreatedAt,
		"updated_at":     cfg.UpdatedAt,
	}, nil
}

func (r *tenantRegistry) openBackend(cfg tenantBackendConfig) (*store.Store, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
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
