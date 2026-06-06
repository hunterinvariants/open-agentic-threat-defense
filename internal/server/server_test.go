package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestWriteEndpointsRequireTokenWhenConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/demo", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestWriteEndpointsAcceptBearerToken(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/demo", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestReadEndpointsDoNotRequireToken(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHealthAndReadyEndpoints(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
	}
}

func TestRBACRequiresTokenForReadWhenUsersConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{Name: "viewer", TokenHash: auth.HashToken("view-token"), Roles: []string{auth.RoleViewer}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer view-token")
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRBACBlocksInsufficientRole(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{Name: "viewer", TokenHash: auth.HashToken("view-token"), Roles: []string{auth.RoleViewer}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(`{"kind":"finding","asset_id":"a1"}`))
	req.Header.Set("Authorization", "Bearer view-token")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRBACBlocksAuditForViewer(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{Name: "viewer", TokenHash: auth.HashToken("view-token"), Roles: []string{auth.RoleViewer}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.Header.Set("Authorization", "Bearer view-token")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	audits := app.store.ListAudits()
	if len(audits) != 1 || audits[0].Action != "auth.authorize" || audits[0].Outcome != "denied" {
		t.Fatalf("unexpected audit log: %#v", audits)
	}
}

func TestSessionLoginAndLogout(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{Name: "alice", TokenHash: auth.HashToken("secret"), Roles: []string{auth.RoleOperator}}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"username":"alice","token":"secret"}`))
	loginRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusAccepted {
		t.Fatalf("expected login 202, got %d: %s", loginRec.Code, loginRec.Body.String())
	}
	var loginPayload struct {
		Authenticated bool   `json:"authenticated"`
		Mode          string `json:"mode"`
		Principal     struct {
			Name string `json:"name"`
		} `json:"principal"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginPayload); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if !loginPayload.Authenticated || loginPayload.Mode != "session" || loginPayload.Principal.Name != "alice" {
		t.Fatalf("unexpected login payload: %#v", loginPayload)
	}
	cookies := loginRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	statusReq.AddCookie(cookies[0])
	statusRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected authenticated status 200, got %d", statusRec.Code)
	}

	logoutReq := httptest.NewRequest(http.MethodDelete, "/api/session", nil)
	logoutReq.AddCookie(cookies[0])
	logoutRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("expected logout 200, got %d", logoutRec.Code)
	}

	statusReq = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	statusReq.AddCookie(cookies[0])
	statusRec = httptest.NewRecorder()
	app.Routes().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", statusRec.Code)
	}
}

func TestEmptyListEndpointsReturnArrays(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	for _, path := range []string{"/api/events", "/api/alerts", "/api/responses"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
		var payload []json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("%s: response is not a JSON array: %s", path, rec.Body.String())
		}
		if len(payload) != 0 {
			t.Fatalf("%s: expected empty array, got %d entries", path, len(payload))
		}
	}
}

func TestResponseApprovalEndpoint(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if _, err := app.LoadDemo(); err != nil {
		t.Fatalf("load demo: %v", err)
	}
	alerts := app.store.ListAlerts()
	if len(alerts) == 0 {
		t.Fatal("expected demo alerts")
	}

	planReq := httptest.NewRequest(http.MethodPost, "/api/responses", strings.NewReader(`{"alert_id":"`+alerts[0].ID+`"}`))
	planRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(planRec, planReq)
	if planRec.Code != http.StatusAccepted {
		t.Fatalf("expected plan 202, got %d: %s", planRec.Code, planRec.Body.String())
	}
	actions := app.store.ListActions()
	var actionID string
	for _, action := range actions {
		if action.ApprovalStatus == "required" {
			actionID = action.ID
			break
		}
	}
	if actionID == "" {
		t.Fatal("expected at least one action requiring approval")
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+actionID+`","approved_by":"alice"}`))
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusAccepted {
		t.Fatalf("expected approve 202, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	var approved struct {
		ApprovalStatus string `json:"approval_status"`
		ApprovedBy     string `json:"approved_by"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.ApprovalStatus != "approved" || approved.ApprovedBy != "alice" {
		t.Fatalf("unexpected approval response: %#v", approved)
	}
	audits := app.store.ListAudits()
	if len(audits) == 0 {
		t.Fatal("expected audit events")
	}
	foundApproval := false
	for _, audit := range audits {
		if audit.Action == "responses.approve" && audit.ResourceID == actionID && audit.Outcome == "accepted" {
			foundApproval = true
			break
		}
	}
	if !foundApproval {
		t.Fatalf("expected response approval audit event, got %#v", audits)
	}
}

func TestAlertWebhookExportsNewAlerts(t *testing.T) {
	exported := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Type   string         `json:"type"`
			Alerts []domain.Alert `json:"alerts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode webhook: %v", err)
		}
		if payload.Type != "oadtd.alerts" {
			t.Fatalf("unexpected payload type: %s", payload.Type)
		}
		exported += len(payload.Alerts)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	app, err := NewWithOptions(Options{AlertWebhookURL: webhook.URL})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	if _, err := app.LoadDemo(); err != nil {
		t.Fatalf("load demo: %v", err)
	}
	if exported == 0 {
		t.Fatal("expected webhook export")
	}
	if app.lastExportError() != "" {
		t.Fatalf("unexpected export error: %s", app.lastExportError())
	}
}
