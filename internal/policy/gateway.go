package policy

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

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

	verdict, reason, risk, findings := e.assessGatewayRequest(request, tool, command, signal, alerts)

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
	if len(findings) > 0 {
		metadata["signals"] = strings.Join(findings, ";")
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

func (e *Engine) assessGatewayRequest(request domain.ToolCallRequest, tool string, command string, signal string, alerts []domain.Alert) (domain.GatewayVerdict, string, domain.Severity, []string) {
	payloadVariants := gatewayTextVariants(
		command,
		request.Signal,
		request.Destination,
		strings.Join(request.Labels, " "),
		metadataText(request.Metadata),
	)
	findings := make([]string, 0, 6)
	verdict := domain.GatewayAllow
	reason := fmt.Sprintf("tool %q matched the approved manifest", tool)
	risk := severityForAlerts(alerts)

	switch {
	case strings.TrimSpace(request.ToolName) == "":
		verdict = domain.GatewayDeny
		reason = "tool name is required"
		risk = maxSeverity(risk, domain.SeverityHigh)
	case hasAlertRule(alerts, "deception.canary.hit"):
		verdict = domain.GatewayDeny
		reason = "deception asset touched or canary signal detected"
		risk = maxSeverity(risk, domain.SeverityCritical)
	case hasAlertRule(alerts, "agent.tool.unapproved"):
		verdict = domain.GatewayDeny
		reason = fmt.Sprintf("tool %q is not on the approved manifest", tool)
		risk = maxSeverity(risk, domain.SeverityHigh)
	default:
		if match, term, variant := gatewayContainsAny(payloadVariants, secretTerms()); match {
			verdict = domain.GatewayRequireApproval
			if variant != term {
				reason = "obfuscated sensitive material referenced by the tool call"
				findings = append(findings, fmt.Sprintf("secret_term=%s", term), fmt.Sprintf("variant=%s", variant))
			} else {
				reason = "sensitive material referenced by the tool call"
				findings = append(findings, fmt.Sprintf("secret_term=%s", term))
			}
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if match, term, variant := gatewayContainsAny(payloadVariants, discoveryTerms()); match {
			verdict = domain.GatewayRequireApproval
			if variant != term {
				reason = "obfuscated discovery-style tool usage requires approval"
			} else {
				reason = "discovery-style tool usage requires approval"
			}
			findings = append(findings, fmt.Sprintf("discovery_term=%s", term))
			risk = maxSeverity(risk, domain.SeverityHigh)
		} else if hasAlertRule(alerts, "network.egress.unknown") || hasAlertRule(alerts, "process.discovery.chain") || hasAlertRule(alerts, "model.runtime.suspicious") {
			verdict = domain.GatewayRequireApproval
			reason = "tool call requires operator approval"
			risk = maxSeverity(risk, severityForAlerts(alerts))
		} else if len(alerts) > 0 {
			verdict = domain.GatewayRequireApproval
			reason = "tool call produced security alerts and requires review"
			risk = maxSeverity(risk, severityForAlerts(alerts))
		}
	}

	if risk == "" {
		risk = domain.SeverityInfo
	}
	if len(findings) > 0 && verdict == domain.GatewayAllow {
		verdict = domain.GatewayRequireApproval
	}
	return verdict, reason, risk, findings
}

func decisionID(requestID string) string {
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		return ""
	}
	return "dec-" + requestID
}

func maxSeverity(a, b domain.Severity) domain.Severity {
	if a.Rank() >= b.Rank() {
		return a
	}
	return b
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

func gatewayTextVariants(values ...string) []string {
	seen := make(map[string]struct{})
	variants := make([]string, 0, len(values)*4)
	add := func(text string) {
		text = normalizeGatewayText(text)
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		seen[text] = struct{}{}
		variants = append(variants, text)
	}
	for _, value := range values {
		add(value)
		add(compactGatewayText(value))
		for _, token := range tokenizeGatewayText(value) {
			add(token)
			add(compactGatewayText(token))
			for _, decoded := range decodeGatewayCandidates(token) {
				add(decoded)
				add(compactGatewayText(decoded))
			}
		}
	}
	return variants
}

func gatewayContainsAny(variants []string, terms []string) (bool, string, string) {
	for _, term := range terms {
		for _, needle := range termVariants(term) {
			for _, variant := range variants {
				if needle != "" && strings.Contains(variant, needle) {
					return true, term, variant
				}
			}
		}
	}
	return false, "", ""
}

func termVariants(term string) []string {
	seen := make(map[string]struct{})
	variants := make([]string, 0, 2)
	add := func(text string) {
		text = normalizeGatewayText(text)
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		seen[text] = struct{}{}
		variants = append(variants, text)
	}
	add(term)
	add(compactGatewayText(term))
	return variants
}

func normalizeGatewayText(text string) string {
	return strings.TrimSpace(strings.ToLower(text))
}

func compactGatewayText(text string) string {
	var builder strings.Builder
	builder.Grow(len(text))
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func tokenizeGatewayText(text string) []string {
	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '+' || r == '/')
	})
	return tokens
}

func decodeGatewayCandidates(token string) []string {
	if !looksBase64Like(token) {
		return nil
	}
	candidates := []string{token}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(padBase64(token))
		if err != nil {
			continue
		}
		if text := printableGatewayText(decoded); text != "" {
			candidates = append(candidates, text)
		}
	}
	return candidates
}

func looksBase64Like(token string) bool {
	if len(token) < 8 {
		return false
	}
	for _, r := range token {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '+', r == '/', r == '-', r == '_', r == '=':
		default:
			return false
		}
	}
	return true
}

func padBase64(token string) string {
	token = strings.TrimSpace(token)
	switch len(token) % 4 {
	case 2:
		return token + "=="
	case 3:
		return token + "="
	default:
		return token
	}
}

func printableGatewayText(decoded []byte) string {
	if len(decoded) == 0 {
		return ""
	}
	text := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(decoded))
	return normalizeGatewayText(text)
}
