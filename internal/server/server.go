package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/correlator"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/exporter"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
	"github.com/open-agentic-threat-defense/oadtd/internal/response"
	"github.com/open-agentic-threat-defense/oadtd/internal/store"
)

const Version = "0.1.0-mvp"

type App struct {
	store      *store.Store
	policy     *policy.Engine
	correlator *correlator.Correlator
	responder  *response.Planner
	webDir     string
	apiToken   string
	webhook    exporter.Webhook
	exportMu   sync.RWMutex
	exportErr  string
	startedAt  time.Time
	counter    atomic.Uint64
}

type Options struct {
	WebDir            string
	DataPath          string
	APIToken          string
	Policy            policy.Config
	CorrelationWindow time.Duration
	AlertWebhookURL   string
	AlertWebhookToken string
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
	st, err := store.NewWithPath(options.DataPath)
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
		apiToken:   options.APIToken,
		webhook: exporter.Webhook{
			URL:   options.AlertWebhookURL,
			Token: options.AlertWebhookToken,
		},
		startedAt: time.Now().UTC(),
	}, nil
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/events", a.handleEvents)
	mux.HandleFunc("/api/alerts", a.handleAlerts)
	mux.HandleFunc("/api/assets", a.handleAssets)
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

	events, alerts, assets, actions := a.store.Counts()
	storageMode := "memory"
	if a.store.PersistencePath() != "" {
		storageMode = "file"
	}
	writeJSON(w, http.StatusOK, domain.Status{
		Version:          Version,
		UptimeSeconds:    int64(time.Since(a.startedAt).Seconds()),
		EventCount:       events,
		AlertCount:       alerts,
		AssetCount:       assets,
		ActionCount:      actions,
		StartedAt:        a.startedAt,
		StorageMode:      storageMode,
		StoragePath:      a.store.PersistencePath(),
		LastStorageError: a.store.LastPersistenceError(),
		LastExportError:  a.lastExportError(),
	})
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
	writeJSON(w, http.StatusAccepted, map[string]any{
		"alerts_created": len(alerts),
		"alerts":         alerts,
	})
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
		if a.apiToken == "" || !strings.HasPrefix(r.URL.Path, "/api/") || isReadOnly(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if !constantTimeEqual(readToken(r), a.apiToken) {
			writeError(w, http.StatusUnauthorized, errors.New("missing or invalid API token"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isReadOnly(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func readToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[len("Bearer "):])
	}
	return strings.TrimSpace(r.Header.Get("X-OATD-Token"))
}

func constantTimeEqual(got string, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
