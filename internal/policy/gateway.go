package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func (e *Engine) GateToolCall(request domain.ToolCallRequest) domain.ToolCallDecision {
	now := time.Now().UTC()
	tool := strings.ToLower(strings.TrimSpace(request.ToolName))
	if tool == "" {
		tool = "unknown"
	}

	command := strings.TrimSpace(strings.Join([]string{request.Command, request.Arguments}, " "))
	signal := strings.TrimSpace(strings.Join([]string{request.Signal, metadataText(request.Metadata)}, " "))
	event := domain.Event{
		ID:          request.ID,
		Timestamp:   request.Timestamp,
		Kind:        domain.EventAgentToolCall,
		AssetID:     request.AssetID,
		Hostname:    request.Hostname,
		Actor:       request.Actor,
		Destination: request.Destination,
		ToolName:    tool,
		Command:     command,
		Signal:      signal,
		Labels:      append([]string(nil), request.Labels...),
		Metadata:    cloneStringMap(request.Metadata),
	}

	alerts := e.Evaluate(event)
	if request.Destination != "" && isExternalDestination(request.Destination) && !e.isApprovedEgress(request.Destination) {
		alerts = append(alerts, newAlert(
			"network.egress.unknown",
			"Unknown outbound destination",
			"Tool call referenced an outbound destination outside the approved egress list.",
			domain.SeverityMedium,
			domain.Event{
				ID:          event.ID,
				Timestamp:   event.Timestamp,
				Kind:        domain.EventNetworkFlow,
				AssetID:     event.AssetID,
				Hostname:    event.Hostname,
				Actor:       event.Actor,
				SourceIP:    event.SourceIP,
				Destination: request.Destination,
				Signal:      request.Signal,
				Labels:      append([]string(nil), request.Labels...),
				Metadata:    cloneStringMap(request.Metadata),
			},
			map[string]string{
				"destination": request.Destination,
				"tool":        tool,
				"actor":       request.Actor,
			},
		))
	}

	verdict := domain.GatewayAllow
	reason := fmt.Sprintf("tool %q matched the approved manifest", tool)
	risk := severityForAlerts(alerts)

	switch {
	case strings.TrimSpace(request.ToolName) == "":
		verdict = domain.GatewayDeny
		reason = "tool name is required"
		risk = domain.SeverityHigh
	case hasAlertRule(alerts, "deception.canary.hit"):
		verdict = domain.GatewayDeny
		reason = "deception asset touched or canary signal detected"
		risk = domain.SeverityCritical
	case hasAlertRule(alerts, "agent.tool.unapproved"):
		verdict = domain.GatewayDeny
		reason = fmt.Sprintf("tool %q is not on the approved manifest", tool)
		risk = domain.SeverityHigh
	case hasAlertRule(alerts, "agent.secret.exposure"):
		verdict = domain.GatewayRequireApproval
		reason = "sensitive material referenced by the tool call"
	case hasAlertRule(alerts, "network.egress.unknown"), hasAlertRule(alerts, "process.discovery.chain"), hasAlertRule(alerts, "model.runtime.suspicious"):
		verdict = domain.GatewayRequireApproval
		reason = "tool call requires operator approval"
	}

	payload := strings.ToLower(strings.Join([]string{
		command,
		request.Signal,
		request.Destination,
		strings.Join(request.Labels, " "),
		metadataText(request.Metadata),
	}, " "))
	if verdict == domain.GatewayAllow && containsAny(payload, secretTerms()) {
		verdict = domain.GatewayRequireApproval
		reason = "sensitive material referenced by the tool call"
		risk = domain.SeverityCritical
	}
	if verdict == domain.GatewayAllow && containsAny(payload, discoveryTerms()) {
		verdict = domain.GatewayRequireApproval
		reason = "discovery-style tool usage requires approval"
		risk = domain.SeverityHigh
	}
	if verdict == domain.GatewayAllow && len(alerts) > 0 {
		verdict = domain.GatewayRequireApproval
		reason = "tool call produced security alerts and requires review"
	}
	if risk == "" {
		risk = domain.SeverityInfo
	}

	metadata := cloneStringMap(request.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["tool"] = tool
	metadata["actor"] = request.Actor
	metadata["asset_id"] = request.AssetID
	metadata["hostname"] = request.Hostname
	metadata["verdict"] = string(verdict)
	metadata["risk"] = string(risk)
	if request.Destination != "" {
		metadata["destination"] = request.Destination
	}
	if request.Signal != "" {
		metadata["signal"] = request.Signal
	}
	if request.ID != "" {
		metadata["request_id"] = request.ID
	}

	return domain.ToolCallDecision{
		ID:        decisionID(request.ID),
		RequestID: request.ID,
		ToolName:  tool,
		Verdict:   verdict,
		Reason:    reason,
		Risk:      risk,
		CreatedAt: now,
		Alerts:    append([]domain.Alert(nil), alerts...),
		Metadata:  metadata,
	}
}

func decisionID(requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ""
	}
	return "dec-" + requestID
}

func severityForAlerts(alerts []domain.Alert) domain.Severity {
	risk := domain.SeverityInfo
	for _, alert := range alerts {
		if alert.Severity.Rank() > risk.Rank() {
			risk = alert.Severity
		}
	}
	return risk
}

func hasAlertRule(alerts []domain.Alert, ruleID string) bool {
	for _, alert := range alerts {
		if alert.RuleID == ruleID {
			return true
		}
	}
	return false
}

func metadataText(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, metadata[key]))
	}
	return strings.Join(parts, " ")
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

func secretTerms() []string {
	return []string{
		"secret",
		"token",
		"credential",
		"password",
		"api_key",
		"ssh_key",
		"bearer",
	}
}
