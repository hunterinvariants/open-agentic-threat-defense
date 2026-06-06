package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/correlator"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
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
	startedAt  time.Time
	counter    atomic.Uint64
}

func New(webDir string) *App {
	if webDir == "" {
		webDir = "web"
	}
	return &App{
		store:      store.New(),
		policy:     policy.NewDefault(),
		correlator: correlator.New(30 * time.Minute),
		responder:  response.NewDryRun(),
		webDir:     webDir,
		startedAt:  time.Now().UTC(),
	}
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/events", a.handleEvents)
	mux.HandleFunc("/api/alerts", a.handleAlerts)
	mux.HandleFunc("/api/assets", a.handleAssets)
	mux.HandleFunc("/api/responses", a.handleResponses)
	mux.HandleFunc("/api/policies", a.handlePolicies)
	mux.HandleFunc("/api/demo", a.handleDemo)
	mux.Handle("/", a.staticHandler())
	return withSecurityHeaders(mux)
}

func (a *App) LoadDemo() []domain.Alert {
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
	writeJSON(w, http.StatusOK, domain.Status{
		Version:       Version,
		UptimeSeconds: int64(time.Since(a.startedAt).Seconds()),
		EventCount:    events,
		AlertCount:    alerts,
		AssetCount:    assets,
		ActionCount:   actions,
		StartedAt:     a.startedAt,
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
		alerts := a.ingest(events)
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
		a.store.AddActions(actions)
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
	alerts := a.LoadDemo()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"alerts_created": len(alerts),
		"alerts":         alerts,
	})
}

func (a *App) ingest(events []domain.Event) []domain.Alert {
	alerts := []domain.Alert{}
	for i := range events {
		a.prepareEvent(&events[i])
		a.store.AddEvent(events[i])
		alerts = append(alerts, a.policy.Evaluate(events[i])...)
	}

	alerts = append(alerts, a.correlator.Evaluate(a.store.ListEvents())...)
	a.prepareAlerts(alerts)
	return a.store.AddAlerts(alerts)
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
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return nil, err
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
