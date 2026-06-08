package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func init() {
	_ = os.Setenv("OATD_SESSION_SECRET", "test-session-secret")
}

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

func TestReadEndpointsRequireTokenWhenConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
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
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d", rec.Code)
	}
}

func TestSSORoutesBypassTokenAuth(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	for _, path := range []string{"/api/sso/oidc/login", "/api/sso/saml/login"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		app.Routes().ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("%s: expected route to bypass token auth, got 401", path)
		}
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

func TestStatusIncludesHAFields(t *testing.T) {
	app, err := NewWithOptions(Options{
		InstanceName: "blue",
		PublicURL:    "https://oatd.example",
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got := status["instance_name"]; got != "blue" {
		t.Fatalf("expected instance_name blue, got %#v", got)
	}
	if got := status["public_url"]; got != "https://oatd.example" {
		t.Fatalf("expected public_url, got %#v", got)
	}
}

func TestAuditChainEndpointReturnsSnapshot(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/api/audit/chain", nil)
	auditReq.Header.Set("Authorization", "Bearer secret")
	auditRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(auditRec, auditReq)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", auditRec.Code)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(auditRec.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode chain snapshot: %v", err)
	}
	if _, ok := snapshot["valid"]; !ok {
		t.Fatalf("expected chain validity in response: %#v", snapshot)
	}
}

func TestGatewayProxyForwardsAllowedToolCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("expected sanitized headers to strip authorization, got %q", got)
		}
		if got := r.Header.Get("X-Forwarded-For"); got != "" {
			t.Fatalf("expected sanitized headers to strip x-forwarded-for, got %q", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
		ProxyAllowLocalTargets: true,
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	body := `{"upstream_url":"` + upstream.URL + `","tool_call":{"asset_id":"asset-1","actor":"agent-1","tool_name":"asset_inventory","command":"list"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/gateway/proxy", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected upstream status, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"upstream_body":"{\"ok\":true}"`) {
		t.Fatalf("expected upstream body in response, got %s", rec.Body.String())
	}
}

func TestGatewayProxyRejectsPrivateUpstreamFromRemote(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/proxy", strings.NewReader(`{"upstream_url":"http://127.0.0.1:1234","tool_call":{"tool_name":"asset_inventory"}}`))
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected private upstream rejection, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMCPProxyForwardsAllowedToolsCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-OATD-Proxy"); got != "mcp" {
			t.Fatalf("expected proxy header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
		MCPUpstreamURL: upstream.URL,
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mcp/proxy", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"asset_inventory","arguments":{"asset_id":"a1"}}}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected upstream status, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"result":{"ok":true}`) {
		t.Fatalf("expected upstream json-rpc result, got %s", rec.Body.String())
	}
}

func TestMCPProxyBlocksUnapprovedTool(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
		MCPUpstreamURL: upstream.URL,
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mcp/proxy", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"whoami"}}}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected blocked status, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"approval required"`) && !strings.Contains(rec.Body.String(), `"blocked by policy"`) {
		t.Fatalf("expected json-rpc error, got %s", rec.Body.String())
	}
}

func TestMCPProxyApprovalForwardsApprovedCall(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("X-OATD-Proxy"); got != "mcp" {
			t.Fatalf("expected proxy header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{{
			Name:      "operator",
			TokenHash: auth.HashToken("secret"),
			Roles:     []string{auth.RoleOperator},
		}},
		MCPUpstreamURL: upstream.URL,
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mcp/proxy", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"asset_inventory","arguments":{"command":"inventory scan token=abc123"}}}`))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected approval required, got %d body=%s", rec.Code, rec.Body.String())
	}
	var decision struct {
		Error struct {
			Data struct {
				Action struct {
					ID string `json:"id"`
				} `json:"action"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode approval decision: %v", err)
	}
	if decision.Error.Data.Action.ID == "" {
		t.Fatal("expected pending mcp action")
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+decision.Error.Data.Action.ID+`","approved_by":"alice"}`))
	approveReq.Header.Set("Authorization", "Bearer secret")
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusAccepted {
		t.Fatalf("expected approval 202, got %d body=%s", approveRec.Code, approveRec.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected approved MCP call to be forwarded once, got %d", calls)
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

func TestGatewayDecisionEndpoint(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(`{
		"id":"gw-1",
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inventory scan",
		"arguments":"token=abc123"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var decision struct {
		Verdict  string `json:"verdict"`
		Reason   string `json:"reason"`
		ToolName string `json:"tool_name"`
		Action   struct {
			ID              string `json:"id"`
			Type            string `json:"type"`
			ApprovalStatus  string `json:"approval_status"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"action"`
		RecommendedActions []struct {
			Type string `json:"type"`
		} `json:"recommended_actions"`
		Alerts []struct {
			RuleID string `json:"rule_id"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode gateway decision: %v", err)
	}
	if decision.Verdict != "require_approval" {
		t.Fatalf("expected approval verdict, got %#v", decision)
	}
	if decision.ToolName != "asset_inventory" {
		t.Fatalf("unexpected tool name: %#v", decision)
	}
	if decision.Action.ID == "" || decision.Action.Type != "gateway_tool_call" || decision.Action.ApprovalStatus != "required" {
		t.Fatalf("expected pending gateway action: %#v", decision.Action)
	}
	if len(decision.Alerts) == 0 {
		t.Fatalf("expected alerts in gateway decision: %#v", decision)
	}
	if len(decision.RecommendedActions) == 0 {
		t.Fatalf("expected recommended actions in gateway decision: %#v", decision)
	}
	audits := app.store.ListAudits()
	if len(audits) == 0 || audits[0].Action != "gateway.decide" || audits[0].Outcome != "require_approval" {
		t.Fatalf("unexpected audit log: %#v", audits)
	}
	if len(app.store.ListAlerts()) == 0 {
		t.Fatal("expected gateway alerts to be stored")
	}
}

func TestGatewayDecisionApprovalReleasesStubTool(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inventory scan",
		"arguments":"token=abc123"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var decision struct {
		Action struct {
			ID string `json:"id"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode gateway decision: %v", err)
	}
	if decision.Action.ID == "" {
		t.Fatal("expected pending action")
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+decision.Action.ID+`","approved_by":"alice"}`))
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusAccepted {
		t.Fatalf("expected approval 202, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	var approved struct {
		ExecutionStatus string `json:"execution_status"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.ExecutionStatus != "proceeded" {
		t.Fatalf("expected gateway execution to proceed, got %#v", approved)
	}
}

func TestGatewayDecisionCanaryBlocksAndRecordsEvidence(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"read protected vault",
		"labels":["canary","deception"]
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var decision struct {
		Verdict string `json:"verdict"`
		Action  struct {
			ID              string `json:"id"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"action"`
		Alerts []struct {
			RuleID string `json:"rule_id"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode gateway decision: %v", err)
	}
	if decision.Verdict != "deny" {
		t.Fatalf("expected deny verdict, got %#v", decision)
	}
	if decision.Action.ID == "" || decision.Action.ExecutionStatus != "blocked" {
		t.Fatalf("expected blocked containment evidence, got %#v", decision.Action)
	}
	if len(decision.Alerts) == 0 {
		t.Fatal("expected canary alerts")
	}
}

func TestBlockedGatewayActionCannotBeApproved(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"read protected vault",
		"labels":["canary","deception"]
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var decision struct {
		Action struct {
			ID string `json:"id"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("decode gateway decision: %v", err)
	}
	if decision.Action.ID == "" {
		t.Fatal("expected blocked action")
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+decision.Action.ID+`","approved_by":"alice"}`))
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 for blocked gateway action, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
}

func TestGatewayDecisionRequiresTokenWhenConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/decide", strings.NewReader(`{"tool_name":"asset_inventory"}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGatewayExecuteRequiresTokenWhenConfigured(t *testing.T) {
	app, err := NewWithOptions(Options{APIToken: "secret"})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{"tool_name":"asset_inventory"}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestGatewayExecuteEndpointExecutesAllowedTool(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{
		"id":"gw-1",
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inventory scan"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Status   string `json:"status"`
		Result   string `json:"result"`
		Decision struct {
			Verdict string `json:"verdict"`
		} `json:"decision"`
		Action struct {
			ID              string `json:"id"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if result.Status != "executed" || result.Decision.Verdict != "allow" || result.Result == "" {
		t.Fatalf("unexpected execute response: %#v", result)
	}
	if result.Action.ID == "" || result.Action.ExecutionStatus != "executed" {
		t.Fatalf("expected executed action, got %#v", result.Action)
	}
}

func TestGatewayExecuteEndpointQueuesApproval(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inspect inventory",
		"arguments":"token=abc123"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Status string `json:"status"`
		Action struct {
			ID              string `json:"id"`
			ApprovalStatus  string `json:"approval_status"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if result.Status != "pending_approval" || result.Action.ID == "" || result.Action.ApprovalStatus != "required" {
		t.Fatalf("unexpected pending response: %#v", result)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+result.Action.ID+`","approved_by":"alice"}`))
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusAccepted {
		t.Fatalf("expected approval 202, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	var approved struct {
		ExecutionStatus string `json:"execution_status"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.ExecutionStatus != "proceeded" {
		t.Fatalf("expected gateway execution to proceed, got %#v", approved)
	}
}

func TestGatewayExecuteEndpointBlocksCanary(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"read protected vault",
		"labels":["canary","deception"]
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Status string `json:"status"`
		Action struct {
			ID              string `json:"id"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if result.Status != "blocked" || result.Action.ID == "" || result.Action.ExecutionStatus != "blocked" {
		t.Fatalf("unexpected blocked response: %#v", result)
	}
}

func TestGatewayQueueListsPendingActions(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inspect inventory",
		"arguments":"token=abc123"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	queueReq := httptest.NewRequest(http.MethodGet, "/api/gateway/queue", nil)
	queueRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(queueRec, queueReq)
	if queueRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", queueRec.Code, queueRec.Body.String())
	}
	var payload struct {
		PendingActions []struct {
			ID              string `json:"id"`
			ApprovalStatus  string `json:"approval_status"`
			ExecutionStatus string `json:"execution_status"`
		} `json:"pending_actions"`
	}
	if err := json.Unmarshal(queueRec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode queue: %v", err)
	}
	if len(payload.PendingActions) != 1 || payload.PendingActions[0].ApprovalStatus != "required" || payload.PendingActions[0].ExecutionStatus != "" {
		t.Fatalf("unexpected queue payload: %#v", payload)
	}
}

func TestGatewayActionLookupReturnsAction(t *testing.T) {
	app, err := NewWithOptions(Options{})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/gateway/execute", strings.NewReader(`{
		"asset_id":"agent-1",
		"hostname":"agent-1",
		"actor":"local-agent",
		"tool_name":"asset_inventory",
		"command":"inspect inventory",
		"arguments":"token=abc123"
	}`))
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Action struct {
			ID string `json:"id"`
		} `json:"action"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}

	actionReq := httptest.NewRequest(http.MethodGet, "/api/gateway/actions/"+result.Action.ID, nil)
	actionRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(actionRec, actionReq)
	if actionRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", actionRec.Code, actionRec.Body.String())
	}
	var action struct {
		ID             string `json:"id"`
		ApprovalStatus string `json:"approval_status"`
	}
	if err := json.Unmarshal(actionRec.Body.Bytes(), &action); err != nil {
		t.Fatalf("decode action: %v", err)
	}
	if action.ID != result.Action.ID || action.ApprovalStatus != "required" {
		t.Fatalf("unexpected action lookup: %#v", action)
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
		t.Fatalf("expected the session cookie to be revoked after logout, got %d", statusRec.Code)
	}

	statusReq = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	statusRec = httptest.NewRecorder()
	app.Routes().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie after logout, got %d", statusRec.Code)
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

func TestResponseApprovalExecutesWebhook(t *testing.T) {
	var got struct {
		Type   string `json:"type"`
		Action struct {
			ID string `json:"id"`
		} `json:"response_action"`
	}
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode response webhook: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	app, err := NewWithOptions(Options{
		ResponseWebhookURL: webhook.URL,
	})
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
		ExecutionStatus string `json:"execution_status"`
	}
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.ExecutionStatus != "sent" {
		t.Fatalf("expected execution status sent, got %#v", approved)
	}
	if got.Type != "oadtd.response_action" || got.Action.ID != actionID {
		t.Fatalf("unexpected response webhook payload: %#v", got)
	}
}

func TestResponsePlanningExportsIncidentTicket(t *testing.T) {
	var got struct {
		Type   string `json:"type"`
		Action struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"response_action"`
	}
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode incident webhook: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	app, err := NewWithOptions(Options{
		TicketWebhookURL: webhook.URL,
	})
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
	var ticketAction domain.ResponseAction
	for _, action := range actions {
		if action.Type == "create_incident_ticket" {
			ticketAction = action
			break
		}
	}
	if ticketAction.ID == "" {
		t.Fatal("expected ticket action")
	}
	if ticketAction.ExecutionStatus != "sent" {
		t.Fatalf("expected ticket action execution to be sent, got %#v", ticketAction)
	}
	if got.Type != "oadtd.incident_ticket" || got.Action.ID != ticketAction.ID || got.Action.Type != "create_incident_ticket" {
		t.Fatalf("unexpected incident webhook payload: %#v", got)
	}
}

func TestGitHubResponseConnectors(t *testing.T) {
	var issuePath string
	var dispatchPath string
	issueSeen := false
	dispatchSeen := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/issues"):
			issueSeen = true
			issuePath = r.URL.Path
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/dispatches"):
			dispatchSeen = true
			dispatchPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	app, err := NewWithOptions(Options{
		GitHubAPIBaseURL:   server.URL,
		GitHubOwner:        "owner",
		GitHubRepo:         "repo",
		GitHubToken:        "token",
		GitHubWorkflowFile: "runbook.yml",
		GitHubWorkflowRef:  "main",
	})
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
	var ticketActionID string
	var approvalActionID string
	for _, action := range actions {
		switch action.Type {
		case "create_incident_ticket":
			ticketActionID = action.ID
		case "isolate_host":
			approvalActionID = action.ID
		}
	}
	if ticketActionID == "" || approvalActionID == "" {
		t.Fatalf("expected ticket and approval actions, got %#v", actions)
	}

	approveReq := httptest.NewRequest(http.MethodPost, "/api/responses/approve", strings.NewReader(`{"action_id":"`+approvalActionID+`","approved_by":"alice"}`))
	approveRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusAccepted {
		t.Fatalf("expected approve 202, got %d: %s", approveRec.Code, approveRec.Body.String())
	}
	if !issueSeen || !dispatchSeen {
		t.Fatalf("expected github issue and dispatch calls, issue=%v dispatch=%v", issueSeen, dispatchSeen)
	}
	if issuePath != "/repos/owner/repo/issues" {
		t.Fatalf("unexpected issue path: %s", issuePath)
	}
	if dispatchPath != "/repos/owner/repo/actions/workflows/runbook.yml/dispatches" {
		t.Fatalf("unexpected dispatch path: %s", dispatchPath)
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

func TestTenantIsolationFiltersReadPaths(t *testing.T) {
	app, err := NewWithOptions(Options{
		Users: []auth.UserConfig{
			{Name: "alice", Tenant: "tenant-a", TokenHash: auth.HashToken("alice-secret"), Roles: []string{auth.RoleIngestor, auth.RoleViewer}},
			{Name: "bob", Tenant: "tenant-b", TokenHash: auth.HashToken("bob-secret"), Roles: []string{auth.RoleViewer}},
		},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(`{"kind":"finding","asset_id":"asset-a","hostname":"asset-a","signal":"tenant-a"}`))
	req.Header.Set("Authorization", "Bearer alice-secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected ingest 202, got %d: %s", rec.Code, rec.Body.String())
	}

	readReq := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	readReq.Header.Set("Authorization", "Bearer alice-secret")
	readRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("expected tenant-a read 200, got %d", readRec.Code)
	}
	if !strings.Contains(readRec.Body.String(), "asset-a") {
		t.Fatalf("expected tenant-a event in response, got %s", readRec.Body.String())
	}

	otherReq := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	otherReq.Header.Set("Authorization", "Bearer bob-secret")
	otherRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("expected tenant-b read 200, got %d", otherRec.Code)
	}
	if strings.Contains(otherRec.Body.String(), "asset-a") {
		t.Fatalf("expected tenant-b isolation, got %s", otherRec.Body.String())
	}
}

func TestPhysicalTenantIsolationUsesSeparateStores(t *testing.T) {
	dir := t.TempDir()
	app, err := NewWithOptions(Options{
		DataPath:               filepath.Join(dir, "default.json"),
		TenantIsolationMode:    "physical",
		TenantRegistryPath:     filepath.Join(dir, "tenants.json"),
		TenantDataPathTemplate: filepath.Join(dir, "{tenant}.json"),
		Users: []auth.UserConfig{
			{Name: "alice", Tenant: "tenant-a", TokenHash: auth.HashToken("alice-secret"), Roles: []string{auth.RoleIngestor, auth.RoleViewer}},
			{Name: "bob", Tenant: "tenant-b", TokenHash: auth.HashToken("bob-secret"), Roles: []string{auth.RoleViewer}},
		},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader(`{"kind":"finding","asset_id":"asset-a","hostname":"asset-a","signal":"tenant-a"}`))
	req.Header.Set("Authorization", "Bearer alice-secret")
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected ingest 202, got %d: %s", rec.Code, rec.Body.String())
	}

	readReq := httptest.NewRequest(http.MethodGet, "/api/events", nil)
	readReq.Header.Set("Authorization", "Bearer bob-secret")
	readRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(readRec, readReq)
	if readRec.Code != http.StatusOK {
		t.Fatalf("expected tenant-b read 200, got %d", readRec.Code)
	}
	if strings.Contains(readRec.Body.String(), "asset-a") {
		t.Fatalf("expected tenant-b physical isolation, got %s", readRec.Body.String())
	}
	statusReq := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	statusReq.Header.Set("Authorization", "Bearer alice-secret")
	statusRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", statusRec.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got := status["tenant_isolation"]; got != "physical" {
		t.Fatalf("expected physical isolation, got %#v", got)
	}
	if got := status["tenant_count"]; got == nil || got.(float64) < 2 {
		t.Fatalf("expected tenant_count >= 2, got %#v", got)
	}
}

func TestTenantAdminCRUDPersistsMetadata(t *testing.T) {
	dir := t.TempDir()
	app, err := NewWithOptions(Options{
		DataPath:               filepath.Join(dir, "default.json"),
		TenantIsolationMode:    "physical",
		TenantRegistryPath:     filepath.Join(dir, "tenants.json"),
		TenantDataPathTemplate: filepath.Join(dir, "{tenant}.json"),
		Users: []auth.UserConfig{
			{Name: "admin", Tenant: "default", TokenHash: auth.HashToken("admin-secret"), Roles: []string{auth.RoleAdmin}},
		},
	})
	if err != nil {
		t.Fatalf("new app: %v", err)
	}

	createReq := httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(`{
		"tenant":"tenant-z",
		"mode":"file",
		"admins":["alice","bob"],
		"policy_profile":"strict",
		"retention_window":"30d",
		"sso_profile":"oidc",
		"backup_target":"s3://archive/oatd",
		"labels":["prod","finance"],
		"notes":"mission critical"
	}`))
	createReq.Header.Set("Authorization", "Bearer admin-secret")
	createRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected create 201, got %d: %s", createRec.Code, createRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/tenants/tenant-z", nil)
	getReq.Header.Set("Authorization", "Bearer admin-secret")
	getRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected tenant get 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	if !strings.Contains(getRec.Body.String(), `"policy_profile":"strict"`) || !strings.Contains(getRec.Body.String(), `"admins":["alice","bob"]`) {
		t.Fatalf("expected tenant metadata in response, got %s", getRec.Body.String())
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/api/tenants/tenant-z", strings.NewReader(`{
		"retention_window":"720h",
		"backup_target":"s3://archive/oatd/nightly",
		"notes":"updated"
	}`))
	updateReq.Header.Set("Authorization", "Bearer admin-secret")
	updateRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("expected tenant update 200, got %d: %s", updateRec.Code, updateRec.Body.String())
	}
	if !strings.Contains(updateRec.Body.String(), `"retention_window":"720h"`) {
		t.Fatalf("expected updated retention in response, got %s", updateRec.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/tenants/tenant-z", nil)
	deleteReq.Header.Set("Authorization", "Bearer admin-secret")
	deleteRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected tenant delete 200, got %d: %s", deleteRec.Code, deleteRec.Body.String())
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/api/tenants/tenant-z", nil)
	missingReq.Header.Set("Authorization", "Bearer admin-secret")
	missingRec := httptest.NewRecorder()
	app.Routes().ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("expected deleted tenant to disappear, got %d: %s", missingRec.Code, missingRec.Body.String())
	}
}
