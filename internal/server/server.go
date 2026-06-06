package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/correlator"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/exporter"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
	"github.com/open-agentic-threat-defense/oadtd/internal/response"
	"github.com/open-agentic-threat-defense/oadtd/internal/store"
)

const Version = "0.1.0-mvp"

type App struct {
	store           *store.Store
	policy          *policy.Engine
	correlator      *correlator.Correlator
	responder       *response.Planner
	webDir          string
	auth            *auth.Authenticator
	webhook         exporter.Webhook
	ticketWebhook   exporter.Webhook
	responseWebhook exporter.Webhook
	github          exporter.GitHub
	exportMu        sync.RWMutex
	exportErr       string
	startedAt       time.Time
	counter         atomic.Uint64
}

type Options struct {
	WebDir               string
	DataPath             string
	PostgresDSN          string
	APIToken             string
	Users                []auth.UserConfig
	Policy               policy.Config
	CorrelationWindow    time.Duration
	AlertWebhookURL      string
	AlertWebhookToken    string
	TicketWebhookURL     string
	TicketWebhookToken   string
	ResponseWebhookURL   string
	ResponseWebhookToken string
	GitHubAPIBaseURL     string
	GitHubOwner          string
	GitHubRepo           string
	GitHubToken          string
	GitHubWorkflowFile   string
	GitHubWorkflowRef    string
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
	if options.CorrelationWindow == 0 {
		options.CorrelationWindow = 30 * time.Minute
	}
	return &App{
		store:      st,
		policy:     policy.New(options.Policy),
		correlator: correlator.New(options.CorrelationWindow),
		responder:  response.NewDryRun(),
		webDir:     options.WebDir,
		auth:       auth.New(options.Users, options.APIToken),
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
		startedAt: time.Now().UTC(),
	}, nil
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.handleHealth)
	mux.HandleFunc("/readyz", a.handleReady)
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/session", a.handleSession)
	mux.HandleFunc("/api/events", a.handleEvents)
	mux.HandleFunc("/api/alerts", a.handleAlerts)
	mux.HandleFunc("/api/assets", a.handleAssets)
	mux.HandleFunc("/api/audit", a.handleAudit)
	mux.HandleFunc("/api/responses/approve", a.handleResponseApproval)
	mux.HandleFunc("/api/responses", a.handleResponses)
	mux.HandleFunc("/api/policies", a.handlePolicies)
	mux.HandleFunc("/api/demo", a.handleDemo)
	mux.Handle("/", a.staticHandler())
	return withSecurityHeaders(a.withAuth(mux))
}

func (a *App) LoadDemo() ([]domain.Alert, error) {
	events := DemoEvents(time.Now().UTC())
	for i := range events {
		events[i].ID = ""
	}
	return a.ingest(events)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}

	events, alerts, assets, actions, audits := a.store.Counts()
	writeJSON(w, http.StatusOK, domain.Status{
		Version:          Version,
		UptimeSeconds:    int64(time.Since(a.startedAt).Seconds()),
		EventCount:       events,
		AlertCount:       alerts,
		AssetCount:       assets,
		ActionCount:      actions,
		AuditCount:       audits,
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
		if a.auth == nil || !a.auth.Enabled() {
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
		if info, ok := a.auth.Session(r); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "session",
				"principal":     info.Principal,
				"expires_at":    info.ExpiresAt,
			})
			return
		}
		if principal, ok := a.auth.Authenticate(r); ok {
			writeJSON(w, http.StatusOK, map[string]any{
				"authenticated": true,
				"mode":          "token",
				"principal":     principal,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
		})
	case http.MethodPost:
		if a.auth == nil || !a.auth.Enabled() {
			writeJSON(w, http.StatusAccepted, map[string]any{
				"authenticated": true,
				"mode":          "open",
				"principal": auth.Principal{
					Name:  "anonymous",
					Roles: []string{auth.RoleAdmin},
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
		info, sessionID, ok := a.auth.Login(req.Username, req.Token)
		if !ok {
			a.recordAudit(r, auth.Principal{Name: "anonymous"}, "auth.login", "session", "", "denied", map[string]string{
				"username": strings.TrimSpace(req.Username),
			})
			writeError(w, http.StatusUnauthorized, errors.New("invalid credentials"))
			return
		}
		a.auth.SetSessionCookie(w, sessionID, info.ExpiresAt, r.TLS != nil)
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
		if a.auth == nil || !a.auth.Enabled() {
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

func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.store.ListEvents())
	case http.MethodPost:
		events, err := decodeEvents(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		alerts, err := a.ingest(events)
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

func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.store.ListAlerts())
}

func (a *App) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.store.ListAssets())
}

func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.store.ListAudits())
}

func (a *App) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.policy.Rules())
}

func (a *App) handleResponseApproval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
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
	action, ok, err := a.store.ApproveAction(req.ActionID, req.ApprovedBy, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
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
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.store.ListActions())
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
		alert, ok := a.store.GetAlert(req.AlertID)
		if !ok {
			writeError(w, http.StatusNotFound, errors.New("alert not found"))
			return
		}
		actions := a.responder.Plan(alert)
		for i := range actions {
			a.prepareAction(&actions[i])
		}
		if err := a.store.AddActions(actions); err != nil {
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
	alerts, err := a.LoadDemo()
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
	if a.github.Enabled() {
		if err := a.github.CreateIssue(action); err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": "github_issue",
			})
		} else {
			status = "sent"
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": "github_issue",
			})
		}
	} else if a.ticketWebhook.URL != "" {
		if err := a.ticketWebhook.ExportIncidentTicket(action); err != nil {
			status = "failed"
			executionError = err.Error()
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "failed", map[string]string{
				"error":     err.Error(),
				"connector": "incident_ticket",
			})
		} else {
			status = "sent"
			a.recordAudit(r, principal, "responses.execute", "response_action", action.ID, "accepted", map[string]string{
				"connector": "incident_ticket",
			})
		}
	}
	now := time.Now().UTC()
	recorded, ok, err := a.store.RecordActionExecution(action.ID, now, status, executionError)
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
	recorded, ok, err := a.store.RecordActionExecution(action.ID, now, status, executionError)
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

func (a *App) ingest(events []domain.Event) ([]domain.Alert, error) {
	alerts := []domain.Alert{}
	for i := range events {
		a.prepareEvent(&events[i])
		if err := a.store.AddEvent(events[i]); err != nil {
			return nil, err
		}
		alerts = append(alerts, a.policy.Evaluate(events[i])...)
	}

	alerts = append(alerts, a.correlator.Evaluate(a.store.ListEvents())...)
	a.prepareAlerts(alerts)
	added, err := a.store.AddAlerts(alerts)
	if err != nil {
		return nil, err
	}
	a.exportAlerts(added)
	return added, nil
}

func (a *App) prepareEvent(event *domain.Event) {
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

func (a *App) prepareAlerts(alerts []domain.Alert) {
	now := time.Now().UTC()
	for i := range alerts {
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

func (a *App) prepareAction(action *domain.ResponseAction) {
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

func (a *App) nextID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, a.counter.Add(1))
}

func (a *App) recordAudit(r *http.Request, principal auth.Principal, action string, resourceType string, resourceID string, outcome string, metadata map[string]string) {
	if metadata == nil {
		metadata = make(map[string]string)
	}
	if principal.Name == "" {
		principal.Name = "anonymous"
	}
	event := domain.AuditEvent{
		ID:           a.nextID("aud"),
		Timestamp:    time.Now().UTC(),
		Actor:        principal.Name,
		Roles:        append([]string(nil), principal.Roles...),
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Outcome:      outcome,
		SourceIP:     sourceIP(r),
		UserAgent:    r.UserAgent(),
		Metadata:     metadata,
	}
	_ = a.store.AddAudit(event)
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
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (a *App) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/session" || a.auth == nil || !a.auth.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		if !a.auth.HasUsers() && isReadOnly(r.Method) {
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

func sourceIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
