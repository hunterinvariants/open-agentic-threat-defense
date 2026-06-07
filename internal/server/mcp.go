package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type mcpJSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      any              `json:"id,omitempty"`
	Result  any              `json:"result,omitempty"`
	Error   *mcpJSONRPCError `json:"error,omitempty"`
}

func (a *App) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
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

	if a.gatewayMCPUpstream() == "" {
		writeError(w, http.StatusServiceUnavailable, errors.New("MCP upstream is not configured"))
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("empty request body"))
		return
	}

	var rpc mcpJSONRPCRequest
	if err := json.Unmarshal(raw, &rpc); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if shouldInterceptMCPMethod(rpc.Method) {
		toolCall := a.toolCallFromMCPRequest(rpc)
		decision := a.policy.GateToolCall(toolCall)
		principal := principalFromRequest(r)
		tenant := tenantForPrincipal(principal)
		a.prepareAlerts(decision.Alerts, tenant)
		added, err := a.store.AddAlerts(decision.Alerts)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		decision.Alerts = added
		decision.RecommendedActions = a.recommendedActionsForAlerts(added)

		switch decision.Verdict {
		case domain.GatewayAllow:
			resp, status, err := a.forwardMCPRequest(r, raw, rpc.Method)
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			action := a.gatewayActionFromDecision(toolCall, decision, tenant, "not_required", "executed")
			action.Type = "mcp_proxy"
			action.Metadata["mcp_method"] = rpc.Method
			action.Metadata["mcp_upstream_url"] = a.gatewayMCPUpstream()
			a.prepareAction(&action, tenant)
			if err := a.store.AddActions([]domain.ResponseAction{action}); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			a.recordAudit(r, principal, "mcp.proxy", "tool_call", decision.RequestID, "executed", map[string]string{
				"method":      rpc.Method,
				"tool":        decision.ToolName,
				"risk":        string(decision.Risk),
				"reason":      decision.Reason,
				"destination": a.gatewayMCPUpstream(),
				"action_id":   decisionActionID(&action),
				"status":      fmt.Sprintf("%d", status),
			})
			writeMCPResponse(w, status, resp)
			return
		case domain.GatewayRequireApproval:
			action := a.gatewayActionFromDecision(toolCall, decision, tenant, "required", "")
			action.Type = "mcp_proxy"
			action.Metadata["mcp_method"] = rpc.Method
			action.Metadata["mcp_upstream_url"] = a.gatewayMCPUpstream()
			a.prepareAction(&action, tenant)
			if err := a.store.AddActions([]domain.ResponseAction{action}); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			decision.Action = &action
			a.recordAudit(r, principal, "mcp.proxy", "tool_call", decision.RequestID, "pending_approval", map[string]string{
				"method":      rpc.Method,
				"tool":        decision.ToolName,
				"risk":        string(decision.Risk),
				"reason":      decision.Reason,
				"destination": a.gatewayMCPUpstream(),
				"action_id":   decisionActionID(decision.Action),
			})
			writeJSON(w, http.StatusAccepted, mcpJSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpc.ID,
				Error: &mcpJSONRPCError{
					Code:    425,
					Message: "approval required",
					Data: map[string]any{
						"decision": decision,
						"action":   action,
					},
				},
			})
			return
		case domain.GatewayDeny:
			action := a.gatewayActionFromDecision(toolCall, decision, tenant, "not_required", "blocked")
			action.Type = "mcp_proxy"
			action.Metadata["mcp_method"] = rpc.Method
			action.Metadata["mcp_upstream_url"] = a.gatewayMCPUpstream()
			a.prepareAction(&action, tenant)
			if err := a.store.AddActions([]domain.ResponseAction{action}); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			decision.Action = &action
			a.recordAudit(r, principal, "mcp.proxy", "tool_call", decision.RequestID, "blocked", map[string]string{
				"method":      rpc.Method,
				"tool":        decision.ToolName,
				"risk":        string(decision.Risk),
				"reason":      decision.Reason,
				"destination": a.gatewayMCPUpstream(),
				"action_id":   decisionActionID(decision.Action),
			})
			writeJSON(w, http.StatusForbidden, mcpJSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpc.ID,
				Error: &mcpJSONRPCError{
					Code:    403,
					Message: "blocked by policy",
					Data: map[string]any{
						"decision": decision,
						"action":   action,
					},
				},
			})
			return
		}
	}

	resp, status, err := a.forwardMCPRequest(r, raw, rpc.Method)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeMCPResponse(w, status, resp)
}

func (a *App) forwardMCPRequest(r *http.Request, raw []byte, method string) ([]byte, int, error) {
	upstream, err := url.Parse(a.gatewayMCPUpstream())
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-OATD-Proxy", "mcp")
	req.Header.Set("X-OATD-Method", method)
	if token := strings.TrimSpace(a.gatewayMCPUpstreamToken()); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func (a *App) toolCallFromMCPRequest(rpc mcpJSONRPCRequest) domain.ToolCallRequest {
	toolCall := domain.ToolCallRequest{
		ToolName: "mcp_" + strings.TrimSpace(rpc.Method),
		Signal:   "mcp_method=" + strings.TrimSpace(rpc.Method),
		Metadata: map[string]string{
			"mcp_method": rpc.Method,
		},
	}
	if strings.TrimSpace(a.gatewayMCPUpstream()) != "" {
		toolCall.Metadata["mcp_upstream_url"] = a.gatewayMCPUpstream()
	}
	if len(rpc.Params) == 0 {
		return toolCall
	}

	var params map[string]any
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		toolCall.Command = string(rpc.Params)
		return toolCall
	}
	if value, ok := stringFromAny(params["name"]); ok {
		toolCall.ToolName = value
	}
	if value, ok := stringFromAny(params["uri"]); ok {
		toolCall.Command = value
		toolCall.Arguments = value
	}
	if value, ok := stringFromAny(params["arguments"]); ok {
		toolCall.Arguments = value
	}
	if value, ok := stringFromAny(params["prompt"]); ok {
		toolCall.Command = value
	}
	if value, ok := stringFromAny(params["message"]); ok {
		toolCall.Command = value
	}
	if toolCall.Command == "" {
		toolCall.Command = canonicalJSON(params)
	}
	if toolCall.Arguments == "" {
		toolCall.Arguments = canonicalJSON(params)
	}
	for key, value := range params {
		if valueString, ok := stringFromAny(value); ok {
			toolCall.Metadata["mcp_"+key] = valueString
		}
	}
	return toolCall
}

func shouldInterceptMCPMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case "tools/call", "resources/read", "prompts/get":
		return true
	default:
		return false
	}
}

func canonicalJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func stringFromAny(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed), true
	case json.Number:
		return strings.TrimSpace(typed.String()), true
	case float64:
		return strings.TrimSpace(fmt.Sprintf("%v", typed)), true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	default:
		if value == nil {
			return "", false
		}
		text := canonicalJSON(value)
		if strings.TrimSpace(text) == "" {
			return "", false
		}
		return text, true
	}
}

func writeMCPResponse(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(body) == 0 {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":500,"message":"empty upstream response"}}`))
		return
	}
	_, _ = w.Write(body)
}

func (a *App) gatewayMCPUpstream() string {
	return strings.TrimSpace(a.mcpUpstreamURL)
}

func (a *App) gatewayMCPUpstreamToken() string {
	return strings.TrimSpace(a.mcpUpstreamToken)
}
