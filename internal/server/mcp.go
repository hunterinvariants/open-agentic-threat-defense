package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const mcpUpstreamResponseLimit = 1 << 20

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

	if isMCPPassthroughMethod(rpc.Method) {
		resp, status, err := a.forwardMCPRequest(r.Context(), raw, rpc.Method, a.gatewayMCPUpstream(), a.gatewayMCPUpstreamToken())
		if err != nil {
			writeError(w, http.StatusBadGateway, err)
			return
		}
		writeMCPResponse(w, status, resp)
		return
	}

	if shouldInterceptMCPMethod(rpc.Method) {
		toolCall := a.toolCallFromMCPRequest(rpc)
		decision := a.policy.GateToolCall(toolCall)
		principal := principalFromRequest(r)
		tenant := tenantForPrincipal(principal)
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
			resp, status, err := a.forwardMCPRequest(r.Context(), raw, rpc.Method, a.gatewayMCPUpstream(), a.gatewayMCPUpstreamToken())
			if err != nil {
				writeError(w, http.StatusBadGateway, err)
				return
			}
			action := a.gatewayActionFromDecision(toolCall, decision, tenant, "not_required", "executed")
			action.Type = "mcp_proxy"
			action.Metadata["mcp_method"] = rpc.Method
			action.Metadata["mcp_upstream_url"] = a.gatewayMCPUpstream()
			action.Metadata["mcp_raw_request"] = base64.RawURLEncoding.EncodeToString(raw)
			a.prepareAction(&action, tenant)
			if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
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
			action.Metadata["mcp_raw_request"] = base64.RawURLEncoding.EncodeToString(raw)
			a.prepareAction(&action, tenant)
			if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
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
			action.Metadata["mcp_raw_request"] = base64.RawURLEncoding.EncodeToString(raw)
			a.prepareAction(&action, tenant)
			if err := a.addActionsForTenant([]domain.ResponseAction{action}, tenant); err != nil {
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

	resp, status, err := a.forwardMCPRequest(r.Context(), raw, rpc.Method, a.gatewayMCPUpstream(), a.gatewayMCPUpstreamToken())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeMCPResponse(w, status, resp)
}

func (a *App) forwardMCPRequest(ctx context.Context, raw []byte, method string, upstreamURL string, upstreamToken string) ([]byte, int, error) {
	target, err := validateProxyUpstreamURL(ctx, upstreamURL, true)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-OATD-Proxy", "mcp")
	req.Header.Set("X-OATD-Method", method)
	if token := strings.TrimSpace(upstreamToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := validatedHTTPClient(target)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, mcpUpstreamResponseLimit+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > mcpUpstreamResponseLimit {
		return nil, 0, errors.New("upstream response too large")
	}
	return body, resp.StatusCode, nil
}

type validatedUpstreamTarget struct {
	URL *url.URL
	IP  net.IP
}

func validateProxyUpstreamURL(ctx context.Context, raw string, allowLocalTargets bool) (*validatedUpstreamTarget, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported upstream scheme %q", parsed.Scheme)
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil, errors.New("upstream_url must include a host")
	}
	if isBlockedProxyHost(host) {
		return nil, fmt.Errorf("upstream host %q is not allowed", host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var selected net.IP
	for _, addr := range addrs {
		if isBlockedProxyIP(addr.IP) && !allowLocalTargets {
			return nil, fmt.Errorf("upstream host %q resolves to a blocked address", host)
		}
		if selected == nil && !isBlockedProxyIP(addr.IP) {
			selected = append(net.IP(nil), addr.IP...)
		}
	}
	if selected == nil && len(addrs) > 0 {
		selected = append(net.IP(nil), addrs[0].IP...)
	}
	if selected == nil {
		return nil, errors.New("upstream host resolved to no usable address")
	}
	return &validatedUpstreamTarget{URL: parsed, IP: selected}, nil
}

func isBlockedProxyHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "", "localhost", "metadata.google.internal":
		return true
	}
	return false
}

func isBlockedProxyIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsMulticast() || ip.IsUnspecified()
}

func validatedHTTPClient(target *validatedUpstreamTarget) *http.Client {
	port := target.URL.Port()
	if port == "" {
		if target.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dialAddr := net.JoinHostPort(target.IP.String(), port)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, dialAddr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression:    false,
	}
	if target.URL.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{ServerName: target.URL.Hostname()}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: transport}
}

func sanitizeProxyHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		"accept":           {},
		"content-type":     {},
		"user-agent":       {},
		"x-request-id":     {},
		"x-correlation-id": {},
		"traceparent":      {},
		"tracestate":       {},
	}
	sanitized := make(map[string]string, len(headers))
	for key, value := range headers {
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if _, ok := allowed[key]; !ok {
			continue
		}
		sanitized[http.CanonicalHeaderKey(key)] = value
	}
	return sanitized
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
	return !isMCPPassthroughMethod(method)
}

func isMCPPassthroughMethod(method string) bool {
	switch strings.TrimSpace(method) {
	case "initialize", "notifications/initialized", "ping":
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
