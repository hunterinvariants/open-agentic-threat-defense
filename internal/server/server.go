package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/config"
	"github.com/open-agentic-threat-defense/oadtd/internal/correlator"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/exporter"
	"github.com/open-agentic-threat-defense/oadtd/internal/license"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
	"github.com/open-agentic-threat-defense/oadtd/internal/response"
	"github.com/open-agentic-threat-defense/oadtd/internal/store"
)

const Version = "0.2.0"

type App struct {
	store            *store.Store
	policy           *policy.Engine
	correlator       *correlator.Correlator
	responder        *response.Planner
	webDir           string
	policyPath       string
	threatPackPath   string
	auth             *auth.Authenticator
	trustedProxies   []*net.IPNet
	gatewayLimiter   chan struct{}
	gatewayMu        sync.Mutex
	gatewaySamples   []time.Duration
	gatewayRejected  int
	webhook          exporter.Webhook
	ticketWebhook    exporter.Webhook
	responseWebhook  exporter.Webhook
	github           exporter.GitHub
	jira             exporter.Jira
	servicenow       exporter.ServiceNow
	mcpUpstreamURL         string
	mcpUpstreamToken       string
	proxyAllowLocalTargets bool
	oidc             *oidcProvider
	saml             *samlProvider
	instanceName     string
	publicURL        string
	tenantRegistry   *tenantRegistry
	exportMu         sync.RWMutex
	exportErr        string
	startedAt        time.Time
	counter          atomic.Uint64
	licenseStatus    license.Status
}

type Options struct {
	WebDir                    string
	DataPath                  string
	PostgresDSN               string
	APIToken                  string
	Users                     []auth.UserConfig
	Policy                    policy.Config
	CorrelationWindow         time.Duration
	ThreatPackPath            string
	PolicyPath                string
	DeceptionTokens           []domain.DeceptionToken
	TenantPolicies            []policy.TenantPolicy
	LicenseToken              string
	LicensePublicKey          string
	AlertWebhookURL           string
	AlertWebhookToken         string
	TicketWebhookURL          string
	TicketWebhookToken        string
	ResponseWebhookURL        string
	ResponseWebhookToken      string
	GitHubAPIBaseURL          string
	GitHubOwner               string
	GitHubRepo                string
	GitHubToken               string
	GitHubWorkflowFile        string
	GitHubWorkflowRef         string
	JiraBaseURL               string
	JiraEmail                 string
	JiraAPIToken              string
	JiraProjectKey            string
	JiraIssueType             string
	ServiceNowInstanceURL     string
	ServiceNowUser            string
	ServiceNowPassword        string
	MCPUpstreamURL            string
	MCPUpstreamToken          string
	ProxyAllowLocalTargets    bool
	OIDCIssuerURL             string
	OIDCClientID              string
	OIDCClientSecret          string
	OIDCRedirectURL           string
	OIDCScopes                []string
	OIDCTenantClaim           string
	OIDCRoleClaim             string
	OIDCEmailClaim            string
	PublicURL                 string
	InstanceName              string
	SAMLRootURL               string
	SAMLIDPMetadataURL        string
	SAMLKeyPath               string
	SAMLCertPath              string
	SAMLTenantAttribute       string
	SAMLRoleAttribute         string
	SAMLEmailAttribute        string
	TenantIsolationMode       string
	TenantRegistryPath        string
	TenantPostgresDSNTemplate string
	TenantDataPathTemplate    string
	TrustedProxies            []string
	RetentionWindow           time.Duration
	GatewayMaxInFlight        int
}

func New(webDir string) *App {
	app, err := NewWithOptions(Options{WebDir: webDir})
	if err != nil {
		panic(err)
	}
	return app
}

func NewWithOptions(options Options) (*App, error) {
	if options.WebDir == "" {
		options.WebDir = "web"
	}
	var st *store.Store
	var err error
	if options.PostgresDSN != "" {
		st, err = store.NewWithPostgres(options.PostgresDSN)
	} else {
		st, err = store.NewWithPath(options.DataPath)
	}
	if err != nil {
		return nil, err
	}
	tenantRegistry, err := newTenantRegistry(options.TenantRegistryPath, options.TenantIsolationMode, options.TenantPostgresDSNTemplate, options.TenantDataPathTemplate, st)
	if err != nil {
		return nil, err
	}
	if options.CorrelationWindow == 0 {
		options.CorrelationWindow = 30 * time.Minute
	}
	if options.RetentionWindow < 0 {
		options.RetentionWindow = 0
	}
	trustedProxies, err := parseTrustedProxies(options.TrustedProxies)
	if err != nil {
		return nil, err
	}
	if err := st.SetRetention(options.RetentionWindow); err != nil {
		return nil, err
	}
	gatewayLimit := options.GatewayMaxInFlight
	if gatewayLimit <= 0 {
		gatewayLimit = 64
	}
	authenticator := auth.New(options.Users, options.APIToken)
	oidcProvider, err := newOIDCProvider(options.OIDCIssuerURL, options.OIDCClientID, options.OIDCClientSecret, options.OIDCRedirectURL, options.OIDCScopes, options.OIDCTenantClaim, options.OIDCRoleClaim, options.OIDCEmailClaim, authenticator.SessionKey())
	if err != nil {
		return nil, err
	}
	samlConfigured := strings.TrimSpace(options.SAMLRootURL) != "" ||
		strings.TrimSpace(options.SAMLIDPMetadataURL) != "" ||
		strings.TrimSpace(options.SAMLKeyPath) != "" ||
		strings.TrimSpace(options.SAMLCertPath) != "" ||
		strings.TrimSpace(options.SAMLTenantAttribute) != "" ||
		strings.TrimSpace(options.SAMLRoleAttribute) != "" ||
		strings.TrimSpace(options.SAMLEmailAttribute) != ""
	var samlProvider *samlProvider
	if samlConfigured {
		samlRootURL := defaultString(strings.TrimSpace(options.PublicURL), strings.TrimSpace(options.SAMLRootURL))
		samlProvider, err = newSAMLProvider(samlOptions{
			RootURL:         samlRootURL,
			IDPMetadataURL:  strings.TrimSpace(options.SAMLIDPMetadataURL),
			KeyPath:         strings.TrimSpace(options.SAMLKeyPath),
			CertPath:        strings.TrimSpace(options.SAMLCertPath),
			CompletePath:    "/api/sso/saml/complete",
			LoginPath:       "/api/sso/saml/login",
			MetadataPath:    "/saml/metadata",
			ACSPath:         "/saml/acs",
			TenantAttribute: defaultString(strings.TrimSpace(options.SAMLTenantAttribute), "tenant"),
			RoleAttribute:   defaultString(strings.TrimSpace(options.SAMLRoleAttribute), "roles"),
			NameAttribute:   defaultString(strings.TrimSpace(options.SAMLEmailAttribute), "email"),
		})
		if err != nil {
			return nil, err
		}
	}
	options.Policy.DeceptionTokens = options.DeceptionTokens
	licenseStatus := license.Community()
	if token := strings.TrimSpace(options.LicenseToken); token != "" && strings.TrimSpace(options.LicensePublicKey) != "" {
		licenseStatus = license.Evaluate(token, options.LicensePublicKey, time.Now().UTC())
	}
	policyEngine := policy.New(options.Policy)
	for _, tenantPolicy := range options.TenantPolicies {
		policyEngine.SetTenantPolicy(tenantPolicy)
	}
	return &App{
		store:          st,
		policy:         policyEngine,
		correlator:     correlator.New(options.CorrelationWindow),
		responder:      response.NewDryRun(),
		webDir:         options.WebDir,
		policyPath:     strings.TrimSpace(options.PolicyPath),
		threatPackPath: strings.TrimSpace(options.ThreatPackPath),
		auth:           authenticator,
		trustedProxies: trustedProxies,
		saml:           samlProvider,
		instanceName:   defaultString(strings.TrimSpace(options.InstanceName), "primary"),
		publicURL:      strings.TrimSpace(options.PublicURL),
		tenantRegistry: tenantRegistry,
		gatewayLimiter: make(chan struct{}, gatewayLimit),
		webhook: exporter.Webhook{
			URL:   options.AlertWebhookURL,
			Token: options.AlertWebhookToken,
		},
		ticketWebhook: exporter.Webhook{
			URL:   options.TicketWebhookURL,
			Token: options.TicketWebhookToken,
		},
		responseWebhook: exporter.Webhook{
			URL:   options.ResponseWebhookURL,
			Token: options.ResponseWebhookToken,
		},
		github: exporter.GitHub{
			BaseURL:      options.GitHubAPIBaseURL,
			Owner:        options.GitHubOwner,
			Repo:         options.GitHubRepo,
			Token:        options.GitHubToken,
			WorkflowFile: options.GitHubWorkflowFile,
			WorkflowRef:  options.GitHubWorkflowRef,
		},
		jira: exporter.Jira{
			BaseURL:    options.JiraBaseURL,
			Email:      options.JiraEmail,
			APIToken:   options.JiraAPIToken,
			ProjectKey: options.JiraProjectKey,
			IssueType:  options.JiraIssueType,
		},
		servicenow: exporter.ServiceNow{
			InstanceURL: options.ServiceNowInstanceURL,
			User:        options.ServiceNowUser,
			Password:    options.ServiceNowPassword,
		},
		mcpUpstreamURL:         options.MCPUpstreamURL,
		mcpUpstreamToken:       options.MCPUpstreamToken,
		proxyAllowLocalTargets: options.ProxyAllowLocalTargets,
		oidc:             oidcProvider,
		startedAt:        time.Now().UTC(),
		licenseStatus:    licenseStatus,
	}, nil
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/readyz", a.handleReady)
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/session", a.handleSession)
	mux.HandleFunc("/api/sso/oidc/login", a.handleOIDCLogin)
	mux.HandleFunc("/api/sso/oidc/callback", a.handleOIDCCallback)
	mux.HandleFunc("/api/sso/saml/login", a.handleSAMLLogin)
	mux.Handle("/api/sso/saml/complete", a.requireSAMLAccount(http.HandlerFunc(a.handleSAMLComplete)))
	mux.HandleFunc("/api/gateway/decide", a.handleGatewayDecision)
	mux.HandleFunc("/api/gateway/execute", a.handleGatewayExecute)
	mux.HandleFunc("/api/policy/reload", a.handlePolicyReload)
	mux.HandleFunc("/api/policy/tenants", a.handleTenantPolicies)
	mux.HandleFunc("/api/deception/tokens", a.handleDeceptionTokens)
	mux.HandleFunc("/api/timeline", a.handleTimeline)
	mux.HandleFunc("/api/license", a.handleLicense)
	mux.HandleFunc("/api/gateway/queue", a.handleGatewayQueue)
	mux.HandleFunc("/api/gateway/actions/", a.handleGatewayAction)
	mux.HandleFunc("/api/events", a.handleEvents)
	mux.HandleFunc("/api/alerts", a.handleAlerts)
	mux.HandleFunc("/api/assets", a.handleAssets)
	mux.HandleFunc("/api/audit", a.handleAudit)
	mux.HandleFunc("/api/audit/chain", a.handleAuditChain)
	mux.HandleFunc("/api/tenants", a.handleTenants)
	mux.HandleFunc("/api/tenants/", a.handleTenantBackend)
	mux.HandleFunc("/api/responses/approve", a.handleResponseApproval)
	mux.HandleFunc("/api/responses", a.handleResponses)
	mux.HandleFunc("/api/policies", a.handlePolicies)
	mux.HandleFunc("/api/demo", a.handleDemo)
	mux.HandleFunc("/api/gateway/proxy", a.handleGatewayProxy)
	mux.HandleFunc("/api/mcp/proxy", a.handleMCPProxy)
	if a.saml != nil && a.saml.Enabled() {
		mux.Handle("/saml/", a.saml)
	}
	mux.Handle("/", a.staticHandler())
	return withSecurityHeaders(a.withAuth(mux))
}

func (a *App) LoadDemo() ([]domain.Alert, error) {
	return a.LoadDemoForTenant("default")
}

func (a *App) LoadDemoForTenant(tenant string) ([]domain.Alert, error) {
	events := DemoEvents(time.Now().UTC())
	for i := range events {
		events[i].ID = ""
	}
	return a.ingest(events, tenant)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	tenant := tenantForPrincipal(principalFromRequest(r))
	events, alerts, assets, actions, audits := a.countsForTenant(tenant)
	writeJSON(w, http.StatusOK, domain.Status{
		Version:          Version,
		InstanceName:     a.instanceName,
		PublicURL:        a.publicURL,
		TenantIsolation:  a.tenantIsolationMode(),
		TenantCount:      a.tenantCount(),
		UptimeSeconds:    int64(time.Since(a.startedAt).Seconds()),
		EventCount:       events,
		AlertCount:       alerts,
		AssetCount:       assets,
		ActionCount:      actions,
		AuditCount:       audits,
		GatewayInFlight:  a.gatewayInFlight(),
		GatewayLimit:     cap(a.gatewayLimiter),
		GatewayRejected:  a.gatewayRejectedCount(),
		GatewayP99Millis: int(a.gatewayP99().Milliseconds()),
		StartedAt:        a.startedAt,
		StorageMode:      a.store.PersistenceMode(),
		StoragePath:      a.store.PersistencePath(),
		SchemaVersion:    a.store.SchemaVersion(),
		LastStorageError: a.store.LastPersistenceError(),
		LastExportError:  a.lastExportError(),
	})
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": Version,
	})
}

func (a *App) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"storage_mode":   a.store.PersistenceMode(),
		"schema_version": a.store.SchemaVersion(),
	})
}

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !a.authenticationConfigured() {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "open",
				"sso": map[string]any{
					"oidc": false,
					"saml": false,
				},
				"principal": auth.Principal{
					Name:   "anonymous",
					Tenant: "default",
					Roles:  []string{auth.RoleAdmin},
				},
			})
			return
		}
		if info, ok := a.auth.Session(r); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "session",
				"sso": map[string]any{
					"oidc":           a.oidc != nil && a.oidc.Enabled(),
					"oidc_login_url": "/api/sso/oidc/login",
					"saml":           a.saml != nil && a.saml.Enabled(),
					"saml_login_url": "/api/sso/saml/login",
				},
				"principal":  info.Principal,
				"expires_at": info.ExpiresAt,
			})
			return
		}
		if principal, ok := a.auth.Authenticate(r); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "token",
				"sso": map[string]any{
					"oidc":           a.oidc != nil && a.oidc.Enabled(),
					"oidc_login_url": "/api/sso/oidc/login",
					"saml":           a.saml != nil && a.saml.Enabled(),
					"saml_login_url": "/api/sso/saml/login",
				},
				"principal": principal,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"sso": map[string]any{
				"oidc":           a.oidc != nil && a.oidc.Enabled(),
				"oidc_login_url": "/api/sso/oidc/login",
				"saml":           a.saml != nil && a.saml.Enabled(),
				"saml_login_url": "/api/sso/saml/login",
			},
		})
	case http.MethodPost:
		if !a.authenticationConfigured() {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"authenticated": true,
				"mode":          "open",
				"principal": auth.Principal{
					Name:   "anonymous",
					Tenant: "default",
					Roles:  []string{auth.RoleAdmin},
				},
			})
			return
		}
		var req struct {
			Username string `json:"username"`
			Token    string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		loginKey := a.sourceIP(r)
		wait, err := a.loginRetryAfter(loginKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if wait > 0 {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Seconds()))
			a.recordAudit(r, auth.Principal{Name: "anonymous"}, "auth.login", "session", "", "rate_limited", map[string]string{
				"username":    strings.TrimSpace(req.Username),
				"retry_after": fmt.Sprintf("%.0f", wait.Seconds()),
			})
			writeError(w, http.StatusTooManyRequests, errors.New("login temporarily rate limited"))
			return
		}
		info, sessionID, ok := a.auth.Login(req.Username, req.Token)
		if !ok {
			wait, err := a.recordLoginAttempt(loginKey, false)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			a.recordAudit(r, auth.Principal{Name: "anonymous"}, "auth.login", "session", "", "denied", map[string]string{
				"username":    strings.TrimSpace(req.Username),
				"retry_after": fmt.Sprintf("%.0f", wait.Seconds()),
			})
			writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
			return
		}
		if _, err := a.recordLoginAttempt(loginKey, true); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		a.auth.SetSessionCookie(w, sessionID, info.ExpiresAt, a.requestIsSecure(r))
		a.recordAudit(r, info.Principal, "auth.login", "session", "", "accepted", map[string]string{
			"mode": "session",
		})
		writeJSON(w, http.StatusAccepted, map[string]any{
			"authenticated": true,
			"mode":          "session",
			"principal":     info.Principal,
			"expires_at":    info.ExpiresAt,
		})
	case http.MethodDelete:
		if !a.authenticationConfigured() {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "open",
				"principal": auth.Principal{
					Name:  "anonymous",
					Roles: []string{auth.RoleAdmin},
				},
			})
			return
		}
		info, ok := a.auth.Session(r)
		if ok {
			a.recordAudit(r, info.Principal, "auth.logout", "session", "", "accepted", nil)
			_ = a.auth.Logout(r)
		}
		a.auth.ClearSessionCookie(w)
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
		})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.oidc == nil || !a.oidc.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("oidc sso is not configured"))
		return
	}
	loginURL, stateToken, err := a.oidc.BeginLogin(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    stateToken,
		Path:     "/api/sso/oidc",
		Expires:  time.Now().UTC().Add(oidcStateTTL),
		HttpOnly: true,
		Secure:   a.requestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (a *App) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.oidc == nil || !a.oidc.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("oidc sso is not configured"))
		return
	}
	principal, returnTo, err := a.oidc.HandleCallback(r.Context(), r)
	if err != nil {
		a.auth.ClearSessionCookie(w)
		http.SetCookie(w, &http.Cookie{
			Name:     oidcStateCookieName,
			Value:    "",
			Path:     "/api/sso/oidc",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if !a.tenantAllowedForIdentity(principal.Tenant) {
		a.auth.ClearSessionCookie(w)
		writeError(w, http.StatusUnauthorized, errors.New("tenant is not allowed"))
		return
	}
	info, sessionID, ok := a.auth.MintSession(principal)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("unable to mint session"))
		return
	}
	a.auth.SetSessionCookie(w, sessionID, info.ExpiresAt, a.requestIsSecure(r))
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/api/sso/oidc",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	a.recordAudit(r, principal, "auth.login", "session", "", "accepted", map[string]string{
		"mode": "oidc",
	})
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (a *App) requireSAMLAccount(next http.Handler) http.Handler {
	if a.saml == nil || !a.saml.Enabled() {
		return next
	}
	return a.saml.RequireAccount(next)
}

func (a *App) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.saml == nil || !a.saml.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("saml sso is not configured"))
		return
	}
	returnTo := normalizeReturnTo(r.URL.Query().Get("return_to"))
	target := "/api/sso/saml/complete"
	if returnTo != "" {
		target += "?return_to=" + url.QueryEscape(returnTo)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *App) handleSAMLComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if a.saml == nil || !a.saml.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("saml sso is not configured"))
		return
	}
	session := samlsp.SessionFromContext(r.Context())
	attributes, ok := session.(samlsp.SessionWithAttributes)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("missing saml session"))
		return
	}
	principal, err := a.saml.principalFromAttributes(attributes.GetAttributes())
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if !a.tenantAllowedForIdentity(principal.Tenant) {
		writeError(w, http.StatusUnauthorized, errors.New("tenant is not allowed"))
		return
	}
	info, sessionID, ok := a.auth.MintSession(principal)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("unable to mint session"))
		return
	}
	a.auth.SetSessionCookie(w, sessionID, info.ExpiresAt, a.requestIsSecure(r))
	a.recordAudit(r, principal, "auth.login", "session", "", "accepted", map[string]string{
		"mode": "saml",
	})
	returnTo := normalizeReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	tenant := tenantForPrincipal(principalFromRequest(r))
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.listEventsForTenant(tenant))
	case http.MethodPost:
		events, err := decodeEvents(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		alerts, err := a.ingest(events, tenant)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		a.recordAudit(r, principalFromRequest(r), "events.ingest", "events", "", "accepted", map[string]string{
			"events": fmt.Sprintf("%d", len(events)),
			"alerts": fmt.Sprintf("%d", len(alerts)),
		})
		writeJSON(w, http.StatusAccepted, map[string]any{
			"events_ingested": len(events),
			"alerts_created":  len(alerts),
			"alerts":          alerts,
		})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleGatewayDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	release, ok := a.gatewayCriticalStart(w)
	if !ok {
		return
	}
	defer release()
	start := time.Now()
	defer func() { a.recordGatewayLatency(time.Since(start)) }()
	var req domain.ToolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.prepareToolCallRequest(&req)
	principal := principalFromRequest(r)
	tenant := tenantForPrincipal(principal)
	req.Tenant = tenant

	decision := a.policy.GateToolCall(req)
	a.prepareAlerts(decision.Alerts, tenant)
	added, err := a.addAlertsForTenant(decision.Alerts, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(added) > 0 {
		a.exportAlerts(added)
	}
	decision.Alerts = added
	decision.RecommendedActions = a.recommendedActionsForAlerts(added)
	switch decision.Verdict {
	case domain.GatewayRequireApproval:
		action := a.gatewayActionFromDecision(req, decision, tenant, "required", "")
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision.Action = &action
	case domain.GatewayDeny:
		action := a.gatewayActionFromDecision(req, decision, tenant, "not_required", "blocked")
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision.Action = &action
	}
	a.recordAudit(r, principal, "gateway.decide", "tool_call", decision.RequestID, string(decision.Verdict), map[string]string{
		"tool":        decision.ToolName,
		"asset_id":    req.AssetID,
		"hostname":    req.Hostname,
		"risk":        string(decision.Risk),
		"alerts":      fmt.Sprintf("%d", len(added)),
		"reason":      decision.Reason,
		"destination": req.Destination,
		"action_id":   decisionActionID(decision.Action),
	})
	writeJSON(w, http.StatusAccepted, decision)
}

func (a *App) handleGatewayExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	release, ok := a.gatewayCriticalStart(w)
	if !ok {
		return
	}
	defer release()
	start := time.Now()
	defer func() { a.recordGatewayLatency(time.Since(start)) }()
	var req domain.ToolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a.prepareToolCallRequest(&req)
	principal := principalFromRequest(r)
	tenant := tenantForPrincipal(principal)
	req.Tenant = tenant

	decision := a.policy.GateToolCall(req)
	a.prepareAlerts(decision.Alerts, tenant)
	added, err := a.addAlertsForTenant(decision.Alerts, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if len(added) > 0 {
		a.exportAlerts(added)
	}
	decision.Alerts = added
	decision.RecommendedActions = a.recommendedActionsForAlerts(added)

	response := domain.ToolExecutionResult{
		Decision: decision,
	}

	switch decision.Verdict {
	case domain.GatewayAllow:
		action := a.gatewayActionFromDecision(req, decision, tenant, "not_required", "executed")
		a.prepareAction(&action, tenant)
		executed, result, execErr := a.executeGatewayToolAction(r, principal, action, "executed")
		if execErr != nil {
			writeError(w, http.StatusInternalServerError, execErr)
			return
		}
		response.Status = executed.ExecutionStatus
		response.Result = result
		response.Action = &executed
		a.recordAudit(r, principal, "gateway.execute", "tool_call", decision.RequestID, "executed", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.AssetID,
			"hostname":    req.Hostname,
			"risk":        string(decision.Risk),
			"alerts":      fmt.Sprintf("%d", len(added)),
			"reason":      decision.Reason,
			"destination": req.Destination,
			"action_id":   decisionActionID(response.Action),
		})
		writeJSON(w, http.StatusOK, response)
	case domain.GatewayRequireApproval:
		action := a.gatewayActionFromDecision(req, decision, tenant, "required", "")
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		response.Status = "pending_approval"
		response.Action = &action
		a.recordAudit(r, principal, "gateway.execute", "tool_call", decision.RequestID, "pending_approval", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.AssetID,
			"hostname":    req.Hostname,
			"risk":        string(decision.Risk),
			"alerts":      fmt.Sprintf("%d", len(added)),
			"reason":      decision.Reason,
			"destination": req.Destination,
			"action_id":   decisionActionID(response.Action),
		})
		writeJSON(w, http.StatusAccepted, response)
	case domain.GatewayDeny:
		action := a.gatewayActionFromDecision(req, decision, tenant, "not_required", "blocked")
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		response.Status = "blocked"
		response.Action = &action
		a.recordAudit(r, principal, "gateway.execute", "tool_call", decision.RequestID, "blocked", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.AssetID,
			"hostname":    req.Hostname,
			"risk":        string(decision.Risk),
			"alerts":      fmt.Sprintf("%d", len(added)),
			"reason":      decision.Reason,
			"destination": req.Destination,
			"action_id":   decisionActionID(response.Action),
		})
		writeJSON(w, http.StatusForbidden, response)
	default:
		writeError(w, http.StatusInternalServerError, errors.New("unknown gateway verdict"))
	}
}

func (a *App) handleGatewayProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	release, ok := a.gatewayCriticalStart(w)
	if !ok {
		return
	}
	defer release()
	start := time.Now()
	defer func() { a.recordGatewayLatency(time.Since(start)) }()

	var req struct {
		UpstreamURL string                 `json:"upstream_url"`
		Body        json.RawMessage        `json:"body,omitempty"`
		Headers     map[string]string      `json:"headers,omitempty"`
		ToolCall    domain.ToolCallRequest `json:"tool_call"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.UpstreamURL) == "" {
		writeError(w, http.StatusBadRequest, errors.New("upstream_url is required"))
		return
	}
	parsedUpstream, err := validateProxyUpstreamURL(r.Context(), req.UpstreamURL, a.proxyAllowLocalTargets)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Never store userinfo credentials embedded in the URL in audit/action metadata.
	req.UpstreamURL = redactURLCredentials(req.UpstreamURL)
	if req.ToolCall.ToolName == "" {
		req.ToolCall.ToolName = "proxy_forward"
	}
	req.ToolCall.Destination = req.UpstreamURL
	a.prepareToolCallRequest(&req.ToolCall)
	principal := principalFromRequest(r)
	tenant := tenantForPrincipal(principal)
	req.ToolCall.Tenant = tenant

	decision := a.policy.GateToolCall(req.ToolCall)
	a.prepareAlerts(decision.Alerts, tenant)
	added, err := a.addAlertsForTenant(decision.Alerts, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	decision.Alerts = added
	decision.RecommendedActions = a.recommendedActionsForAlerts(added)

	switch decision.Verdict {
	case domain.GatewayAllow:
		payload := req.Body
		if len(payload) == 0 {
			payload, err = json.Marshal(req.ToolCall)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
		}
		upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, parsedUpstream.URL.String(), bytes.NewReader(payload))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		for key, value := range sanitizeProxyHeaders(req.Headers) {
			upstreamReq.Header.Set(key, value)
		}
		if upstreamReq.Header.Get("Content-Type") == "" {
			upstreamReq.Header.Set("Content-Type", "application/json")
		}
		upstreamReq.Header.Set("X-OATD-Decision", string(decision.Verdict))
		upstreamReq.Header.Set("X-OATD-Tool", decision.ToolName)
		upstreamReq.Header.Set("X-OATD-Request-ID", decision.RequestID)
		client := validatedHTTPClient(parsedUpstream)
		upstreamResp, err := client.Do(upstreamReq)
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		defer upstreamResp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(upstreamResp.Body, mcpUpstreamResponseLimit+1))
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		if len(body) > mcpUpstreamResponseLimit {
			writeError(w, http.StatusBadGateway, errors.New("upstream response too large"))
			return
		}
		action := a.gatewayActionFromDecision(req.ToolCall, decision, tenant, "not_required", "executed")
		action.Type = "gateway_proxy"
		action.Metadata["proxy_upstream_url"] = req.UpstreamURL
		action.Metadata["proxy_upstream_status"] = fmt.Sprintf("%d", upstreamResp.StatusCode)
		action.Metadata["proxy_content_type"] = upstreamResp.Header.Get("Content-Type")
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		a.recordAudit(r, principal, "gateway.proxy", "tool_call", decision.RequestID, "executed", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.ToolCall.AssetID,
			"hostname":    req.ToolCall.Hostname,
			"risk":        string(decision.Risk),
			"reason":      decision.Reason,
			"destination": req.UpstreamURL,
			"action_id":   decisionActionID(&action),
			"status":      fmt.Sprintf("%d", upstreamResp.StatusCode),
		})
		writeJSON(w, upstreamResp.StatusCode, map[string]any{
			"decision":        decision,
			"upstream_status": upstreamResp.StatusCode,
			"upstream_body":   string(body),
			"action":          action,
		})
	case domain.GatewayRequireApproval:
		action := a.gatewayActionFromDecision(req.ToolCall, decision, tenant, "required", "")
		action.Type = "gateway_proxy"
		action.Metadata["proxy_upstream_url"] = req.UpstreamURL
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision.Action = &action
		a.recordAudit(r, principal, "gateway.proxy", "tool_call", decision.RequestID, "pending_approval", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.ToolCall.AssetID,
			"hostname":    req.ToolCall.Hostname,
			"risk":        string(decision.Risk),
			"reason":      decision.Reason,
			"destination": req.UpstreamURL,
			"action_id":   decisionActionID(decision.Action),
		})
		writeJSON(w, http.StatusAccepted, map[string]any{
			"decision": decision,
			"action":   action,
		})
	case domain.GatewayDeny:
		action := a.gatewayActionFromDecision(req.ToolCall, decision, tenant, "not_required", "blocked")
		action.Type = "gateway_proxy"
		action.Metadata["proxy_upstream_url"] = req.UpstreamURL
		a.prepareAction(&action, tenant)
		if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision.Action = &action
		a.recordAudit(r, principal, "gateway.proxy", "tool_call", decision.RequestID, "blocked", map[string]string{
			"tool":        decision.ToolName,
			"asset_id":    req.ToolCall.AssetID,
			"hostname":    req.ToolCall.Hostname,
			"risk":        string(decision.Risk),
			"reason":      decision.Reason,
			"destination": req.UpstreamURL,
			"action_id":   decisionActionID(decision.Action),
		})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"decision": decision,
			"action":   action,
		})
	default:
		writeError(w, http.StatusInternalServerError, errors.New("unknown gateway verdict"))
	}
}

func (a *App) handleGatewayQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	tenant := tenantForPrincipal(principalFromRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"pending_actions": a.listPendingGatewayActionsForTenant(tenant),
	})
}

func (a *App) handleGatewayAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/gateway/actions/")
	id = strings.Trim(id, "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("action id is required"))
		return
	}
	tenant := tenantForPrincipal(principalFromRequest(r))
	action, ok := a.getActionForTenant(id, tenant)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("action not found"))
		return
	}
	writeJSON(w, http.StatusOK, action)
}

func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.listAlertsForTenant(tenantForPrincipal(principalFromRequest(r))))
}

func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.listAssetsForTenant(tenantForPrincipal(principalFromRequest(r))))
}

func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.listAuditsForTenant(tenantForPrincipal(principalFromRequest(r))))
}

func (a *App) handleAuditChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.auditChainForTenant(tenantForPrincipal(principalFromRequest(r))))
}

// isPlatformAdmin returns true for an admin in the default (root) tenant, who
// alone may list every tenant and create new tenant backends.
func isPlatformAdmin(principal auth.Principal) bool {
	return principal.HasAny(auth.RoleAdmin) && tenantOrDefault(principal.Tenant) == "default"
}

// canAdministerTenant authorizes a per-tenant backend operation: a platform
// admin may manage any tenant; otherwise the caller may only manage their own
// tenant or one where their name is listed in the tenant's Admins.
func canAdministerTenant(principal auth.Principal, targetTenant string, record tenantBackendConfig, hasRecord bool) bool {
	if !principal.HasAny(auth.RoleAdmin) {
		return false
	}
	if isPlatformAdmin(principal) {
		return true
	}
	if tenantOrDefault(principal.Tenant) == tenantOrDefault(targetTenant) {
		return true
	}
	if hasRecord {
		for _, name := range record.Admins {
			if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(principal.Name)) {
				return true
			}
		}
	}
	return false
}

func (a *App) handleTenants(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	if !isPlatformAdmin(principal) {
		writeError(w, http.StatusForbidden, errors.New("platform admin (default tenant) required"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.listTenantBackends())
	case http.MethodPost:
		var req struct {
			Tenant          string   `json:"tenant"`
			Mode            string   `json:"mode"`
			PostgresDSN     string   `json:"postgres_dsn"`
			DataPath        string   `json:"data_path"`
			Admins          []string `json:"admins"`
			PolicyProfile   string   `json:"policy_profile"`
			RetentionWindow string   `json:"retention_window"`
			SSOProfile      string   `json:"sso_profile"`
			BackupTarget    string   `json:"backup_target"`
			Labels          []string `json:"labels"`
			Notes           string   `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		record, err := a.registerTenantBackend(req.Tenant, req.Mode, req.PostgresDSN, req.DataPath, req.Admins, req.PolicyProfile, req.RetentionWindow, req.SSOProfile, req.BackupTarget, req.Labels, req.Notes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, record)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleTenantBackend(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	if !principal.HasAny(auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, errors.New("admin role required"))
		return
	}
	if a.tenantRegistry == nil {
		writeError(w, http.StatusNotFound, errors.New("tenant registry is not configured"))
		return
	}
	tenant := strings.TrimPrefix(r.URL.Path, "/api/tenants/")
	tenant = strings.TrimSpace(tenant)
	if tenant == "" || strings.Contains(tenant, "/") {
		writeError(w, http.StatusNotFound, errors.New("tenant not found"))
		return
	}
	record, hasRecord := a.tenantRegistry.get(tenant)
	if !canAdministerTenant(principal, tenant, record, hasRecord) {
		writeError(w, http.StatusForbidden, errors.New("not authorized to administer this tenant"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		if hasRecord {
			writeJSON(w, http.StatusOK, tenantConfigToMap(tenant, record))
			return
		}
		writeError(w, http.StatusNotFound, errors.New("tenant not found"))
	case http.MethodPut:
		var req struct {
			Mode            string   `json:"mode"`
			PostgresDSN     string   `json:"postgres_dsn"`
			DataPath        string   `json:"data_path"`
			Admins          []string `json:"admins"`
			PolicyProfile   string   `json:"policy_profile"`
			RetentionWindow string   `json:"retention_window"`
			SSOProfile      string   `json:"sso_profile"`
			BackupTarget    string   `json:"backup_target"`
			Labels          []string `json:"labels"`
			Notes           string   `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		record, err := a.updateTenantBackend(tenant, req.Mode, req.PostgresDSN, req.DataPath, req.Admins, req.PolicyProfile, req.RetentionWindow, req.SSOProfile, req.BackupTarget, req.Labels, req.Notes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	case http.MethodDelete:
		record, err := a.deleteTenantBackend(tenant)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.policy.Rules())
}

func (a *App) handlePolicyReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	principal := principalFromRequest(r)
	rules, err := a.ReloadPolicy()
	if err != nil {
		a.recordAudit(r, principal, "policy.reload", "policy", "", "failed", map[string]string{"error": err.Error()})
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.recordAudit(r, principal, "policy.reload", "policy", "", "accepted", map[string]string{"rules": fmt.Sprintf("%d", rules)})
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "rules": rules})
}

// ReloadPolicy re-reads the policy and threat-pack files and atomically swaps
// the detection configuration without a restart. The correlation window is set
// at startup and is not hot-reloaded.
func (a *App) ReloadPolicy() (int, error) {
	if a.policyPath == "" && a.threatPackPath == "" {
		return 0, errors.New("no policy or threat-pack file configured to reload")
	}
	cfg, err := config.Load(a.policyPath)
	if err != nil {
		return 0, err
	}
	if a.threatPackPath != "" {
		cfg.ThreatPackPath = a.threatPackPath
	}
	policyCfg, err := cfg.PolicyConfig()
	if err != nil {
		return 0, err
	}
	a.policy.Reload(policyCfg)
	return len(a.policy.Rules()), nil
}

func (a *App) handleDeceptionTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.policy.ListDeceptionTokens())
	case http.MethodPost:
		var token domain.DeceptionToken
		if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		created, err := a.policy.AddDeceptionToken(token)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		a.recordAudit(r, principalFromRequest(r), "deception.register", "deception_token", created.ID, "accepted", map[string]string{
			"name": created.Name,
			"kind": created.Kind,
		})
		writeJSON(w, http.StatusCreated, created)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, errors.New("id query parameter is required"))
			return
		}
		if !a.policy.RemoveDeceptionToken(id) {
			writeError(w, http.StatusNotFound, errors.New("deception token not found"))
			return
		}
		a.recordAudit(r, principalFromRequest(r), "deception.remove", "deception_token", id, "accepted", nil)
		writeJSON(w, http.StatusOK, map[string]any{"removed": true, "id": id})
	default:
		methodNotAllowed(w)
	}
}

type timelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"` // event | alert | action | audit
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	Severity  string    `json:"severity,omitempty"`
}

func (a *App) handleTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	asset := strings.TrimSpace(r.URL.Query().Get("asset_id"))
	if asset == "" {
		writeError(w, http.StatusBadRequest, errors.New("asset_id query parameter is required"))
		return
	}
	tenant := tenantForPrincipal(principalFromRequest(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"asset_id": asset,
		"entries":  a.buildTimeline(tenant, asset),
	})
}

// buildTimeline merges events, alerts, response actions, and audit records for a
// single asset into one chronological investigation view (tenant-scoped).
func (a *App) buildTimeline(tenant string, asset string) []timelineEntry {
	entries := []timelineEntry{}
	for _, e := range a.listEventsForTenant(tenant) {
		if e.AssetID != asset {
			continue
		}
		entries = append(entries, timelineEntry{
			Timestamp: e.Timestamp, Kind: "event", ID: e.ID,
			Title:  string(e.Kind),
			Detail: firstNonEmptyTimeline(e.Signal, e.Command, e.ToolName, e.Process, e.Destination),
		})
	}
	for _, al := range a.listAlertsForTenant(tenant) {
		if al.AssetID != asset {
			continue
		}
		entries = append(entries, timelineEntry{
			Timestamp: al.CreatedAt, Kind: "alert", ID: al.ID,
			Title: al.Title, Detail: al.RuleID, Severity: string(al.Severity),
		})
	}
	for _, ac := range a.listActionsForTenant(tenant) {
		if ac.AssetID != asset {
			continue
		}
		entries = append(entries, timelineEntry{
			Timestamp: ac.CreatedAt, Kind: "action", ID: ac.ID,
			Title: ac.Type, Detail: ac.Reason,
		})
	}
	for _, au := range a.listAuditsForTenant(tenant) {
		if strings.TrimSpace(au.Metadata["asset_id"]) != asset {
			continue
		}
		entries = append(entries, timelineEntry{
			Timestamp: au.Timestamp, Kind: "audit", ID: au.ID,
			Title: au.Action, Detail: au.Outcome,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Timestamp.Before(entries[j].Timestamp) })
	return entries
}

func firstNonEmptyTimeline(values ...string) string {
	for _, value := range values {
		if s := strings.TrimSpace(value); s != "" {
			return s
		}
	}
	return ""
}

func (a *App) handleLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.licenseStatus)
}

// handleTenantPolicies manages org-scoped policy overlays (approved tools and
// egress per tenant). Admin role required for all methods.
func (a *App) handleTenantPolicies(w http.ResponseWriter, r *http.Request) {
	principal := principalFromRequest(r)
	if !principal.HasAny(auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, errors.New("admin role required"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"tenant_policies": a.policy.ListTenantPolicies()})
	case http.MethodPost, http.MethodPut:
		var req policy.TenantPolicy
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		stored, ok := a.policy.SetTenantPolicy(req)
		if !ok {
			writeError(w, http.StatusBadRequest, errors.New("tenant_id is required"))
			return
		}
		a.recordAudit(r, principal, "policy.tenant.set", "policy", stored.TenantID, "accepted", map[string]string{
			"tenant":          stored.TenantID,
			"approved_tools":  fmt.Sprintf("%d", len(stored.ApprovedTools)),
			"approved_egress": fmt.Sprintf("%d", len(stored.ApprovedEgress)),
		})
		writeJSON(w, http.StatusOK, stored)
	case http.MethodDelete:
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenant == "" {
			writeError(w, http.StatusBadRequest, errors.New("tenant_id query parameter is required"))
			return
		}
		removed := a.policy.RemoveTenantPolicy(tenant)
		outcome := "accepted"
		if !removed {
			outcome = "not_found"
		}
		a.recordAudit(r, principal, "policy.tenant.remove", "policy", tenant, outcome, map[string]string{"tenant": tenant})
		if !removed {
			writeError(w, http.StatusNotFound, errors.New("tenant policy not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": true, "tenant_id": tenant})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleResponseApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	release, ok := a.gatewayCriticalStart(w)
	if !ok {
		return
	}
	defer release()
	start := time.Now()
	defer func() { a.recordGatewayLatency(time.Since(start)) }()
	var req struct {
		ActionID   string `json:"action_id"`
		ApprovedBy string `json:"approved_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.ActionID == "" {
		writeError(w, http.StatusBadRequest, errors.New("action_id is required"))
		return
	}
	if req.ApprovedBy == "" {
		req.ApprovedBy = "operator"
	}
	action, ok, err := a.approveActionForTenant(req.ActionID, req.ApprovedBy, time.Now().UTC(), tenantForPrincipal(principalFromRequest(r)))
	if err != nil {
		if strings.Contains(err.Error(), "blocked gateway actions cannot be approved") {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("action not found"))
		return
	}
	tenant := tenantForPrincipal(principalFromRequest(r))
	if !sameTenant(action.Tenant, tenant) {
		writeError(w, http.StatusNotFound, errors.New("action not found"))
		return
	}
	principal := principalFromRequest(r)
	if principal.Name == "" {
		principal.Name = req.ApprovedBy
	}
	a.recordAudit(r, principal, "responses.approve", "response_action", action.ID, "accepted", map[string]string{
		"approved_by": req.ApprovedBy,
		"asset_id":    action.AssetID,
		"action_type": action.Type,
	})
	if action.Type == "create_incident_ticket" {
		var err error
		action, err = a.executeTicketAction(r, principal, action)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	} else {
		var err error
		action, err = a.executeResponseAction(r, principal, action)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusAccepted, action)
}

func (a *App) handleResponses(w http.ResponseWriter, r *http.Request) {
	tenant := tenantForPrincipal(principalFromRequest(r))
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.listActionsForTenant(tenant))
	case http.MethodPost:
		var req struct {
			AlertID string `json:"alert_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.AlertID == "" {
			writeError(w, http.StatusBadRequest, errors.New("alert_id is required"))
			return
		}
		alert, ok := a.getAlertForTenant(req.AlertID, tenant)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("alert not found"))
			return
		}
		actions := a.responder.Plan(alert)
		for i := range actions {
			a.prepareAction(&actions[i], tenant)
		}
		if err := a.addActionsForTenant(actions, tenant); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		for i := range actions {
			if actions[i].Type != "create_incident_ticket" {
				continue
			}
			action, err := a.executeTicketAction(r, principalFromRequest(r), actions[i])
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			actions[i] = action
		}
		a.recordAudit(r, principalFromRequest(r), "responses.plan", "alert", alert.ID, "accepted", map[string]string{
			"actions": fmt.Sprintf("%d", len(actions)),
		})
		writeJSON(w, http.StatusAccepted, actions)
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleDemo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	alerts, err := a.LoadDemoForTenant(tenantForPrincipal(principalFromRequest(r)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	a.recordAudit(r, principalFromRequest(r), "demo.load", "demo", "", "accepted", map[string]string{
		"alerts": fmt.Sprintf("%d", len(alerts)),
	})
	writeJSON(w, http.StatusAccepted, map[string]any{
		"alerts_created": len(alerts),
		"alerts":         alerts,
	})
}

func (a *App) executeTicketAction(r *http.Request, principal auth.Principal, action domain.ResponseAction) (domain.ResponseAction, error) {
	status := "not_configured"
	executionError := ""
	connectors := []struct {
		name    string
		enabled bool
		send    func(domain.ResponseAction) error
	}{
		{"github_issue", a.github.Enabled(), a.github.CreateIssue},
		{"jira_issue", a.jira.Enabled(), a.jira.CreateIncident},
		{"servicenow_incident", a.servicenow.Enabled(), a.servicenow.CreateIncident},
		{"incident_ticket", a.ticketWebhook.URL != "", a.ticketWebhook.ExportIncidentTicket},
	}
	for _, connector := range connectors {
		if !connector.enabled {
			continue
		}
		if err := connector.send(action); err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": connector.name,
			})
		} else {
			status = "sent"
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": connector.name,
			})
		}
		break
	}
	now := time.Now().UTC()
	recorded, ok, err := a.recordActionExecutionForTenant(action.ID, now, status, executionError, tenantForPrincipal(principalFromRequest(r)))
	if err != nil {
		return domain.ResponseAction{}, err
	}
	if ok {
		return recorded, nil
	}
	action.ExecutionStatus = status
	action.ExecutionError = executionError
	action.ExecutedAt = &now
	return action, nil
}

func (a *App) executeResponseAction(r *http.Request, principal auth.Principal, action domain.ResponseAction) (domain.ResponseAction, error) {
	if action.Type == "gateway_tool_call" {
		executed, _, err := a.executeGatewayToolAction(r, principal, action, "proceeded")
		return executed, err
	}
	if action.Type == "mcp_proxy" {
		executed, err := a.executeMCPProxyAction(r, principal, action)
		return executed, err
	}
	status := "not_configured"
	executionError := ""
	if a.github.Enabled() && a.github.WorkflowFile != "" {
		if err := a.github.DispatchWorkflow(action); err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": "github_workflow",
			})
		} else {
			status = "sent"
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": "github_workflow",
			})
		}
	} else if a.responseWebhook.URL != "" {
		if err := a.responseWebhook.ExportResponseAction(action); err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": "response_webhook",
			})
		} else {
			status = "sent"
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": "response_webhook",
			})
		}
	}
	now := time.Now().UTC()
	recorded, ok, err := a.recordActionExecutionForTenant(action.ID, now, status, executionError, tenantForPrincipal(principalFromRequest(r)))
	if err != nil {
		return domain.ResponseAction{}, err
	}
	if ok {
		return recorded, nil
	}
	action.ExecutionStatus = status
	action.ExecutionError = executionError
	action.ExecutedAt = &now
	return action, nil
}

func (a *App) executeMCPProxyAction(r *http.Request, principal auth.Principal, action domain.ResponseAction) (domain.ResponseAction, error) {
	rawValue := strings.TrimSpace(action.Metadata["mcp_raw_request"])
	if rawValue == "" {
		return domain.ResponseAction{}, errors.New("missing mcp raw request")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rawValue)
	if err != nil {
		return domain.ResponseAction{}, fmt.Errorf("decode mcp raw request: %w", err)
	}
	method := strings.TrimSpace(action.Metadata["mcp_method"])
	if method == "" {
		method = "tools/call"
	}
	upstreamURL := strings.TrimSpace(action.Metadata["mcp_upstream_url"])
	if upstreamURL == "" {
		upstreamURL = a.gatewayMCPUpstream()
	}
	if upstreamURL == "" {
		return domain.ResponseAction{}, errors.New("MCP upstream is not configured")
	}
	status := "not_configured"
	executionError := ""
	if action.ApprovalStatus == "approved" {
		resp, code, err := a.forwardMCPRequest(r.Context(), raw, method, upstreamURL, a.gatewayMCPUpstreamToken())
		if err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": "mcp_proxy",
			})
		} else {
			status = "sent"
			action.Metadata["mcp_response_status"] = fmt.Sprintf("%d", code)
			action.Metadata["mcp_response_body"] = string(resp)
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": "mcp_proxy",
			})
		}
	}
	now := time.Now().UTC()
	recorded, ok, err := a.recordActionExecutionForTenant(action.ID, now, status, executionError, tenantForPrincipal(principalFromRequest(r)))
	if err != nil {
		return domain.ResponseAction{}, err
	}
	if ok {
		return recorded, nil
	}
	action.ExecutionStatus = status
	action.ExecutionError = executionError
	action.ExecutedAt = &now
	return action, nil
}

func (a *App) executeGatewayToolAction(r *http.Request, principal auth.Principal, action domain.ResponseAction, status string) (domain.ResponseAction, string, error) {
	now := time.Now().UTC()
	if status == "proceeded" {
		action.ApprovalStatus = "approved"
	}
	result, err := a.runGatewayStubTool(action)
	if err != nil && status != "blocked" {
		action.ExecutionStatus = "failed"
		action.ExecutionError = err.Error()
	} else {
		action.ExecutionStatus = status
		action.ExecutionError = ""
	}
	action.ExecutedAt = &now
	if action.Metadata == nil {
		action.Metadata = make(map[string]string)
	}
	action.Metadata["gateway_execution"] = action.ExecutionStatus
	action.Metadata["gateway_executed_at"] = now.Format(time.RFC3339)
	if result != "" {
		action.Metadata["gateway_result"] = result
	}
	recorded, ok, persistErr := a.recordActionExecutionForTenant(action.ID, now, action.ExecutionStatus, action.ExecutionError, tenantForPrincipal(principalFromRequest(r)))
	if persistErr != nil {
		return domain.ResponseAction{}, "", persistErr
	}
	if ok {
		action = recorded
	} else {
		_ = a.addActionsForTenant([]domain.ResponseAction{action}, tenantForPrincipal(principalFromRequest(r)))
	}
	a.recordAudit(r, principal, "gateway.execute", "response_action", action.ID, "accepted", map[string]string{
		"tool":       action.Target,
		"asset_id":   action.AssetID,
		"request_id": action.Metadata["request_id"],
		"verdict":    action.Metadata["verdict"],
		"execution":  action.ExecutionStatus,
	})
	return action, result, nil
}

func (a *App) runGatewayStubTool(action domain.ResponseAction) (string, error) {
	tool := strings.ToLower(strings.TrimSpace(action.Target))
	asset := strings.TrimSpace(action.AssetID)
	switch tool {
	case "asset_inventory":
		if asset == "" {
			asset = "unknown"
		}
		return fmt.Sprintf("inventory completed for %s", asset), nil
	case "ticket_create":
		if asset == "" {
			asset = "unknown"
		}
		return fmt.Sprintf("ticket stub created for %s", asset), nil
	case "policy_read":
		return "policy manifest returned", nil
	case "siem_search":
		if asset == "" {
			asset = "all-assets"
		}
		return fmt.Sprintf("search completed for %s", asset), nil
	default:
		return fmt.Sprintf("tool %s executed", tool), nil
	}
}

func (a *App) ingest(events []domain.Event, tenant string) ([]domain.Alert, error) {
	tenant = tenantOrDefault(tenant)
	alerts := []domain.Alert{}
	for i := range events {
		a.prepareEvent(&events[i], tenant)
		if err := a.addEventsForTenant([]domain.Event{events[i]}, tenant); err != nil {
			return nil, err
		}
		alerts = append(alerts, a.policy.Evaluate(events[i])...)
	}

	alerts = append(alerts, a.correlator.Evaluate(a.listEventsForTenant(tenant))...)
	a.prepareAlerts(alerts, tenant)
	added, err := a.addAlertsForTenant(alerts, tenant)
	if err != nil {
		return nil, err
	}
	a.exportAlerts(added)
	return added, nil
}

func (a *App) prepareEvent(event *domain.Event, tenant string) {
	event.Tenant = tenantOrDefault(tenant)
	if event.ID == "" {
		event.ID = a.nextID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = make(map[string]string)
	}
}

func (a *App) prepareAlerts(alerts []domain.Alert, tenant string) {
	tenant = tenantOrDefault(tenant)
	now := time.Now().UTC()
	for i := range alerts {
		alerts[i].Tenant = tenant
		if alerts[i].ID == "" {
			alerts[i].ID = a.nextID("alrt")
		}
		if alerts[i].CreatedAt.IsZero() {
			alerts[i].CreatedAt = now
		}
		if alerts[i].Status == "" {
			alerts[i].Status = domain.AlertOpen
		}
		alerts[i].RecommendedActions = a.responder.Plan(alerts[i])
	}
}

func (a *App) prepareAction(action *domain.ResponseAction, tenant string) {
	action.Tenant = tenantOrDefault(tenant)
	if action.ID == "" {
		action.ID = a.nextID("act")
	}
	if action.CreatedAt.IsZero() {
		action.CreatedAt = time.Now().UTC()
	}
	if action.Metadata == nil {
		action.Metadata = make(map[string]string)
	}
}

func (a *App) gatewayActionFromDecision(request domain.ToolCallRequest, decision domain.ToolCallDecision, tenant string, approvalStatus string, executionStatus string) domain.ResponseAction {
	action := domain.ResponseAction{
		Type:            "gateway_tool_call",
		Mode:            "inline",
		AssetID:         request.AssetID,
		Tenant:          tenantOrDefault(tenant),
		Target:          request.ToolName,
		Reason:          decision.Reason,
		ApprovalStatus:  approvalStatus,
		ExecutionStatus: executionStatus,
		Metadata:        cloneStringMap(request.Metadata),
	}
	if action.Metadata == nil {
		action.Metadata = make(map[string]string)
	}
	mergeStringMaps(action.Metadata, decision.Metadata)
	action.Metadata["tenant"] = tenantOrDefault(tenant)
	action.Metadata["request_id"] = request.ID
	action.Metadata["tool"] = strings.TrimSpace(strings.ToLower(request.ToolName))
	action.Metadata["actor"] = request.Actor
	action.Metadata["hostname"] = request.Hostname
	action.Metadata["verdict"] = string(decision.Verdict)
	action.Metadata["risk"] = string(decision.Risk)
	if request.Destination != "" {
		action.Metadata["destination"] = request.Destination
	}
	if request.Signal != "" {
		action.Metadata["signal"] = request.Signal
	}
	if request.Command != "" {
		action.Metadata["command"] = request.Command
	}
	if request.Arguments != "" {
		action.Metadata["arguments"] = request.Arguments
	}
	if len(request.Labels) > 0 {
		action.Metadata["labels"] = strings.Join(request.Labels, ",")
	}
	return action
}

func mergeStringMaps(dst map[string]string, src map[string]string) {
	for key, value := range src {
		if key == "" || value == "" {
			continue
		}
		dst[key] = value
	}
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func decisionActionID(action *domain.ResponseAction) string {
	if action == nil {
		return ""
	}
	return action.ID
}

func (a *App) prepareToolCallRequest(request *domain.ToolCallRequest) {
	if request.ID == "" {
		request.ID = a.nextID("gw")
	}
	if request.Timestamp.IsZero() {
		request.Timestamp = time.Now().UTC()
	}
	if request.Metadata == nil {
		request.Metadata = make(map[string]string)
	}
}

func (a *App) recommendedActionsForAlerts(alerts []domain.Alert) []domain.ResponseAction {
	seen := make(map[string]struct{})
	actions := make([]domain.ResponseAction, 0)
	for _, alert := range alerts {
		for _, action := range alert.RecommendedActions {
			key := strings.Join([]string{action.Type, action.AssetID, action.Target, action.Reason}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			actions = append(actions, action)
		}
	}
	return actions
}

func (a *App) nextID(prefix string) string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%s-%d", prefix, sanitizeIdentifier(a.instanceName), a.counter.Add(1))
	}
	return fmt.Sprintf("%s-%s-%d-%s", prefix, sanitizeIdentifier(a.instanceName), a.counter.Add(1), hex.EncodeToString(buf))
}

func sanitizeIdentifier(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "default"
	}
	builder := strings.Builder{}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "default"
	}
	return result
}

func (a *App) gatewayCriticalStart(w http.ResponseWriter) (func(), bool) {
	// Per-instance backpressure via an in-process semaphore. This intentionally
	// does NOT pin a database connection per in-flight request: the previous
	// advisory-lock lease held a pooled *sql.Conn for the entire request, so when
	// concurrent gateway calls exceeded the connection pool the handlers' own
	// alert/action/audit writes could not acquire a connection and the critical
	// decision path deadlocked (db.Conn was also called with a non-cancellable
	// context, so saturation blocked indefinitely instead of returning 429).
	if a.gatewayLimiter == nil {
		return func() {}, true
	}
	select {
	case a.gatewayLimiter <- struct{}{}:
		return func() {
			<-a.gatewayLimiter
		}, true
	default:
		a.gatewayMu.Lock()
		a.gatewayRejected++
		a.gatewayMu.Unlock()
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, errors.New("gateway is saturated"))
		return nil, false
	}
}

func (a *App) gatewayInFlight() int {
	if a.store != nil && a.store.PersistenceMode() == "postgres" {
		return 0
	}
	if a.gatewayLimiter == nil {
		return 0
	}
	return len(a.gatewayLimiter)
}

func (a *App) gatewayRejectedCount() int {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	return a.gatewayRejected
}

func (a *App) recordGatewayLatency(duration time.Duration) {
	if duration <= 0 {
		return
	}
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	a.gatewaySamples = append(a.gatewaySamples, duration)
	if len(a.gatewaySamples) > 256 {
		a.gatewaySamples = append([]time.Duration(nil), a.gatewaySamples[len(a.gatewaySamples)-256:]...)
	}
}

func (a *App) gatewayP99() time.Duration {
	a.gatewayMu.Lock()
	defer a.gatewayMu.Unlock()
	if len(a.gatewaySamples) == 0 {
		return 0
	}
	samples := append([]time.Duration(nil), a.gatewaySamples...)
	sort.Slice(samples, func(i, j int) bool {
		return samples[i] < samples[j]
	})
	idx := int(float64(len(samples)-1) * 0.99)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(samples) {
		idx = len(samples) - 1
	}
	return samples[idx]
}

func (a *App) recordAudit(r *http.Request, principal auth.Principal, action string, resourceType string, resourceID string, outcome string, metadata map[string]string) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	if principal.Name == "" {
		principal.Name = "anonymous"
	}
	principal.Tenant = tenantOrDefault(principal.Tenant)
	if principal.Tenant != "" {
		metadata["tenant"] = principal.Tenant
	}
	event := domain.AuditEvent{
		ID:           a.nextID("aud"),
		Timestamp:    time.Now().UTC(),
		Tenant:       principal.Tenant,
		Actor:        principal.Name,
		Roles:        append([]string(nil), principal.Roles...),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      outcome,
		SourceIP:     a.sourceIP(r),
		UserAgent:    r.UserAgent(),
		Metadata:     metadata,
	}
	_ = a.addAuditForTenant(event, principal.Tenant)
}

func (a *App) exportAlerts(alerts []domain.Alert) {
	if len(alerts) == 0 || a.webhook.URL == "" {
		return
	}
	if err := a.webhook.ExportAlerts(alerts); err != nil {
		a.setExportError(err.Error())
		return
	}
	a.setExportError("")
}

func (a *App) setExportError(value string) {
	a.exportMu.Lock()
	defer a.exportMu.Unlock()
	a.exportErr = value
}

func (a *App) lastExportError() string {
	a.exportMu.RLock()
	defer a.exportMu.RUnlock()
	return a.exportErr
}

func (a *App) staticHandler() http.Handler {
	root := http.Dir(filepath.Clean(a.webDir))
	files := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func decodeEvents(r *http.Request) ([]domain.Event, error) {
	var raw json.RawMessage
	limited := http.MaxBytesReader(nil, r.Body, 1<<20)
	defer limited.Close()
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("request body must contain a single JSON value")
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("empty request body")
	}
	if strings.HasPrefix(trimmed, "[") {
		var events []domain.Event
		if err := json.Unmarshal(raw, &events); err != nil {
			return nil, err
		}
		return events, nil
	}

	var event domain.Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}
	return []domain.Event{event}, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	message := err.Error()
	if status == http.StatusInternalServerError {
		// Never reflect internal error detail (DB schema/driver diagnostics, SQL
		// fragments, file paths) to clients. Log it server-side and return a
		// generic message instead.
		log.Printf("internal error (500) on request: %v", err)
		message = "internal server error"
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// requiresAuthEvenInOpenMode lists endpoints that must never be reachable
// without configured authentication, regardless of open-mode passthrough.
func requiresAuthEvenInOpenMode(path string) bool {
	return path == "/api/gateway/proxy" || path == "/api/mcp/proxy"
}

func (a *App) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SSRF-capable proxy endpoints must never be served without authentication,
		// even in open mode, to avoid an unauthenticated internal-request vector.
		if !a.authenticationConfigured() && requiresAuthEvenInOpenMode(r.URL.Path) {
			writeError(w, http.StatusServiceUnavailable, errors.New("proxy endpoints require authentication to be configured"))
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/session" || strings.HasPrefix(r.URL.Path, "/api/sso/") || !a.authenticationConfigured() {
			next.ServeHTTP(w, r)
			return
		}
		principal, ok := a.auth.Authenticate(r)
		if !ok {
			a.recordAudit(r, auth.Principal{Name: "anonymous"}, "auth.authenticate", "http_request", r.URL.Path, "denied", map[string]string{
				"method": r.Method,
			})
			writeError(w, http.StatusUnauthorized, errors.New("missing or invalid API token"))
			return
		}
		required := auth.RequiredRoles(r.Method, r.URL.Path)
		if !principal.HasAny(required...) {
			a.recordAudit(r, principal, "auth.authorize", "http_request", r.URL.Path, "denied", map[string]string{
				"method": r.Method,
			})
			writeError(w, http.StatusForbidden, errors.New("insufficient role"))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal))
		next.ServeHTTP(w, r)
	})
}

func isReadOnly(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

type principalContextKey struct{}

func principalFromRequest(r *http.Request) auth.Principal {
	principal, ok := r.Context().Value(principalContextKey{}).(auth.Principal)
	if !ok {
		return auth.Principal{}
	}
	return principal
}

func tenantForPrincipal(principal auth.Principal) string {
	return tenantOrDefault(principal.Tenant)
}

func tenantOrDefault(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func sameTenant(left string, right string) bool {
	return tenantOrDefault(left) == tenantOrDefault(right)
}

func (a *App) authenticationConfigured() bool {
	return (a.auth != nil && a.auth.Enabled()) || (a.oidc != nil && a.oidc.Enabled()) || (a.saml != nil && a.saml.Enabled())
}

func (a *App) tenantAllowedForIdentity(tenant string) bool {
	tenant = tenantOrDefault(tenant)
	if tenant == "default" {
		return true
	}
	if a.tenantRegistry == nil {
		return false
	}
	if _, ok := a.tenantRegistry.get(tenant); ok {
		return true
	}
	return false
}

func (a *App) loginRetryAfter(key string) (time.Duration, error) {
	if a.store != nil && a.store.PersistenceMode() == "postgres" {
		return a.store.LoginRetryAfter(key)
	}
	if a.auth == nil {
		return 0, nil
	}
	return a.auth.LoginRetryAfter(key), nil
}

func (a *App) recordLoginAttempt(key string, success bool) (time.Duration, error) {
	if a.store != nil && a.store.PersistenceMode() == "postgres" {
		return a.store.RecordLoginAttempt(key, success)
	}
	if a.auth == nil {
		return 0, nil
	}
	return a.auth.RecordLoginAttempt(key, success), nil
}

func (a *App) storeForTenant(tenant string) (*store.Store, error) {
	if a.tenantRegistry == nil {
		return a.store, nil
	}
	st, _, err := a.tenantRegistry.ensureTenantStore(tenant)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (a *App) countsForTenant(tenant string) (int, int, int, int, int) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.CountsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return 0, 0, 0, 0, 0
	}
	return st.Counts()
}

func (a *App) listEventsForTenant(tenant string) []domain.Event {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListEventsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListEvents()
}

func (a *App) listAlertsForTenant(tenant string) []domain.Alert {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListAlertsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListAlerts()
}

func (a *App) listAssetsForTenant(tenant string) []domain.Asset {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListAssetsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListAssets()
}

func (a *App) listAuditsForTenant(tenant string) []domain.AuditEvent {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListAuditsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListAudits()
}

func (a *App) auditChainForTenant(tenant string) store.AuditChainSnapshot {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.AuditChainForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return store.AuditChainSnapshot{}
	}
	return st.AuditChain()
}

func (a *App) listActionsForTenant(tenant string) []domain.ResponseAction {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListActionsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListActions()
}

func (a *App) listPendingGatewayActionsForTenant(tenant string) []domain.ResponseAction {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ListPendingGatewayActionsForTenant(tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil
	}
	return st.ListPendingGatewayActions()
}

func (a *App) getActionForTenant(id string, tenant string) (domain.ResponseAction, bool) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.GetActionForTenant(id, tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return domain.ResponseAction{}, false
	}
	return st.GetAction(id)
}

func (a *App) getAlertForTenant(id string, tenant string) (domain.Alert, bool) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.GetAlertForTenant(id, tenant)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return domain.Alert{}, false
	}
	return st.GetAlert(id)
}

func (a *App) addEventsForTenant(events []domain.Event, tenant string) error {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		for _, event := range events {
			if err := a.store.AddEvent(event); err != nil {
				return err
			}
		}
		return nil
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := st.AddEvent(event); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) addAlertsForTenant(alerts []domain.Alert, tenant string) ([]domain.Alert, error) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.AddAlerts(alerts)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return nil, err
	}
	return st.AddAlerts(alerts)
}

func (a *App) addActionsForTenant(actions []domain.ResponseAction, tenant string) error {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.AddActions(actions)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return err
	}
	return st.AddActions(actions)
}

func (a *App) approveActionForTenant(id string, approvedBy string, approvedAt time.Time, tenant string) (domain.ResponseAction, bool, error) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.ApproveAction(id, approvedBy, approvedAt)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return domain.ResponseAction{}, false, err
	}
	return st.ApproveAction(id, approvedBy, approvedAt)
}

func (a *App) recordActionExecutionForTenant(id string, executedAt time.Time, status string, executionErr string, tenant string) (domain.ResponseAction, bool, error) {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.RecordActionExecution(id, executedAt, status, executionErr)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return domain.ResponseAction{}, false, err
	}
	return st.RecordActionExecution(id, executedAt, status, executionErr)
}

func (a *App) addAuditForTenant(event domain.AuditEvent, tenant string) error {
	if a.tenantRegistry == nil || !a.tenantRegistry.physicalMode {
		return a.store.AddAudit(event)
	}
	st, err := a.storeForTenant(tenant)
	if err != nil {
		return err
	}
	return st.AddAudit(event)
}

func (a *App) listTenantBackends() []map[string]any {
	if a.tenantRegistry == nil {
		return []map[string]any{}
	}
	return a.tenantRegistry.listAsMaps()
}

func (a *App) tenantIsolationMode() string {
	if a.tenantRegistry != nil && a.tenantRegistry.physicalMode {
		return string(tenantIsolationPhysical)
	}
	return string(tenantIsolationLogical)
}

func (a *App) tenantCount() int {
	if a.tenantRegistry == nil {
		return 1
	}
	return a.tenantRegistry.count()
}

func (a *App) registerTenantBackend(tenant string, mode string, postgresDSN string, dataPath string, admins []string, policyProfile string, retentionWindow string, ssoProfile string, backupTarget string, labels []string, notes string) (map[string]any, error) {
	if a.tenantRegistry == nil {
		return nil, errors.New("tenant registry is not configured")
	}
	cfg, err := a.tenantRegistry.registerTenant(tenant, mode, postgresDSN, dataPath, admins, policyProfile, retentionWindow, ssoProfile, backupTarget, labels, notes)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (a *App) updateTenantBackend(tenant string, mode string, postgresDSN string, dataPath string, admins []string, policyProfile string, retentionWindow string, ssoProfile string, backupTarget string, labels []string, notes string) (map[string]any, error) {
	if a.tenantRegistry == nil {
		return nil, errors.New("tenant registry is not configured")
	}
	cfg, err := a.tenantRegistry.updateTenant(tenant, mode, postgresDSN, dataPath, admins, policyProfile, retentionWindow, ssoProfile, backupTarget, labels, notes)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (a *App) deleteTenantBackend(tenant string) (map[string]any, error) {
	if a.tenantRegistry == nil {
		return nil, errors.New("tenant registry is not configured")
	}
	cfg, err := a.tenantRegistry.deleteTenant(tenant)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func normalizeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	if strings.HasPrefix(value, "//") {
		return ""
	}
	return value
}

func (a *App) sourceIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" && a.isTrustedProxy(r.RemoteAddr) {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *App) requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !a.isTrustedProxy(r.RemoteAddr) {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	return proto == "https" || proto == "wss"
}

func (a *App) isTrustedProxy(remoteAddr string) bool {
	if len(a.trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range a.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ValidateListenAddress(listenAddr string, authEnabled bool, insecure bool) error {
	if authEnabled || insecure || isLoopbackListenAddress(listenAddr) {
		return nil
	}
	return errors.New("refusing to listen on a non-loopback address without authentication; use --insecure for local development")
}

func isLoopbackListenAddress(listenAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		host = strings.TrimSpace(listenAddr)
	}
	if host == "localhost" {
		return true
	}
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !strings.Contains(value, "/") {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy address: %s", value)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			value = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy cidr %q: %w", value, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}
