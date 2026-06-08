package policy

import (
	"encoding/base64"
	"encoding/hex"
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
		Tenant:      strings.TrimSpace(request.Tenant),
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
	if request.Destination != "" && isExternalDestination(request.Destination) && !e.egressApprovedForTenant(request.Tenant, request.Destination) {
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

	taint := analyzeGatewayTaint(request, tool, command, signal)
	historyBefore := e.gatewayHistorySnapshot(request)
	verdict, reason, risk, findings := e.assessGatewayRequest(request, tool, command, signal, alerts, taint, historyBefore)
	riskScore, riskFactors := e.scoreGatewayRequest(request, tool, command, signal, alerts, taint, historyBefore, verdict, risk)
	if verdict == domain.GatewayAllow && riskScore >= 70 {
		verdict = domain.GatewayRequireApproval
		reason = "risk score exceeded the inline allow threshold"
	}
	if verdict == domain.GatewayRequireApproval && riskScore >= 90 && taint.HasSourcePrefix("canary:") {
		verdict = domain.GatewayDeny
		reason = "critical taint path exceeded the deny threshold"
	}
	historyAfter := e.recordGatewayHistory(request, verdict, riskScore, append(findings, riskFactors...), tool)

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
	if len(taint.Sources) > 0 {
		metadata["taint_sources"] = strings.Join(taint.Sources, ";")
	}
	if len(taint.Sinks) > 0 {
		metadata["taint_sinks"] = strings.Join(taint.Sinks, ";")
	}
	if len(taint.Flows) > 0 {
		metadata["taint_flows"] = strings.Join(taint.Flows, ";")
	}
	if len(taint.Provenance) > 0 {
		metadata["taint_provenance"] = strings.Join(taint.Provenance, ";")
	}
	metadata["risk_score"] = fmt.Sprintf("%d", riskScore)
	metadata["history_context"] = historyAfter.contextString()
	if len(findings) > 0 {
		metadata["signals"] = strings.Join(findings, ";")
	}
	if len(riskFactors) > 0 {
		metadata["risk_factors"] = strings.Join(riskFactors, ";")
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

func (e *Engine) assessGatewayRequest(request domain.ToolCallRequest, tool string, command string, signal string, alerts []domain.Alert, taint TaintAnalysis, history gatewayHistorySnapshot) (domain.GatewayVerdict, string, domain.Severity, []string) {
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
	provenance := e.checkToolProvenance(tool, request)
	agentIdentity := e.checkAgentIdentity(request)

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
	case provenance == provenanceMismatch:
		verdict = domain.GatewayDeny
		reason = fmt.Sprintf("tool %q provenance mismatch — possible tool spoofing or tampering", tool)
		risk = maxSeverity(risk, domain.SeverityCritical)
		findings = append(findings, "provenance=mismatch")
	case agentIdentity == agentMismatch:
		verdict = domain.GatewayDeny
		reason = fmt.Sprintf("agent identity verification failed for %q — possible impersonation", request.AgentID)
		risk = maxSeverity(risk, domain.SeverityCritical)
		findings = append(findings, "agent_identity=mismatch")
	default:
		if len(taint.Flows) > 0 {
			findings = append(findings, taint.Flows...)
		}
		if taint.HasSourcePrefix("canary:") && len(taint.Sinks) > 0 {
			verdict = domain.GatewayDeny
			reason = "canary source reached a sink and must be contained"
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if taint.HasSourcePrefix("secret:") && len(taint.Sinks) > 0 {
			verdict = domain.GatewayRequireApproval
			if taint.HasSignalPrefix("obfuscated_source:") || taint.HasSignalPrefix("obfuscated_sink:") {
				reason = "obfuscated sensitive source may flow to a sink and requires approval"
			} else {
				reason = "sensitive source may flow to a sink and requires approval"
			}
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if taint.HasSourcePrefix("secret:") {
			verdict = domain.GatewayRequireApproval
			if taint.HasSignalPrefix("obfuscated_source:") {
				reason = "obfuscated sensitive material referenced by the tool call"
			} else {
				reason = "sensitive material referenced by the tool call"
			}
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if taint.HasSourcePrefix("canary:") {
			verdict = domain.GatewayDeny
			reason = "canary source detected"
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if taint.HasSinkPrefix("external_destination:") {
			verdict = domain.GatewayRequireApproval
			reason = "tool call targets an external sink and requires operator approval"
			risk = maxSeverity(risk, domain.SeverityHigh)
		} else if len(taint.Sinks) > 0 && len(taint.Sources) > 0 {
			verdict = domain.GatewayRequireApproval
			reason = "source-to-sink flow requires operator approval"
			risk = maxSeverity(risk, domain.SeverityHigh)
		} else if match, term, variant := gatewayContainsAny(payloadVariants, injectionTerms()); match {
			verdict = domain.GatewayRequireApproval
			if variant != term {
				reason = "obfuscated prompt-injection-like instruction requires approval"
				findings = append(findings, fmt.Sprintf("injection_term=%s", term), fmt.Sprintf("variant=%s", variant))
			} else {
				reason = "prompt-injection-like instruction requires approval"
				findings = append(findings, fmt.Sprintf("injection_term=%s", term))
			}
			risk = maxSeverity(risk, domain.SeverityHigh)
		} else if match, term, variant := gatewayContainsAny(payloadVariants, secretTerms()); match {
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
		} else if match, term, variant := gatewayContainsAny(payloadVariants, lateralMovementTerms()); match {
			verdict = domain.GatewayRequireApproval
			if variant != term {
				reason = "obfuscated lateral-movement tooling requires approval"
			} else {
				reason = "lateral-movement tooling requires approval"
			}
			findings = append(findings, fmt.Sprintf("lateral_term=%s", term))
			risk = maxSeverity(risk, domain.SeverityHigh)
		} else if match, term, variant := gatewayContainsAny(payloadVariants, impactTerms()); match {
			verdict = domain.GatewayRequireApproval
			if variant != term {
				reason = "obfuscated destructive/impact action requires approval"
			} else {
				reason = "destructive/impact action requires approval"
			}
			findings = append(findings, fmt.Sprintf("impact_term=%s", term))
			risk = maxSeverity(risk, domain.SeverityCritical)
		} else if hasAlertRule(alerts, "network.egress.unknown") || hasAlertRule(alerts, "process.discovery.chain") || hasAlertRule(alerts, "model.runtime.suspicious") {
			verdict = domain.GatewayRequireApproval
			reason = "tool call requires operator approval"
			risk = maxSeverity(risk, severityForAlerts(alerts))
		} else if len(alerts) > 0 {
			verdict = domain.GatewayRequireApproval
			reason = "tool call produced security alerts and requires review"
			risk = maxSeverity(risk, severityForAlerts(alerts))
		} else if provenance == provenanceMissing {
			verdict = domain.GatewayRequireApproval
			reason = fmt.Sprintf("tool %q is missing required provenance and needs operator approval", tool)
			risk = maxSeverity(risk, domain.SeverityHigh)
			findings = append(findings, "provenance=missing")
		} else if agentIdentity == agentUnknown {
			verdict = domain.GatewayRequireApproval
			reason = fmt.Sprintf("unregistered agent identity %q requires operator approval", request.AgentID)
			risk = maxSeverity(risk, domain.SeverityHigh)
			findings = append(findings, "agent_identity=unknown")
		} else if agentIdentity == agentUnidentified {
			verdict = domain.GatewayRequireApproval
			reason = "unidentified agent requires operator approval"
			risk = maxSeverity(risk, domain.SeverityHigh)
			findings = append(findings, "agent_identity=unidentified")
		}
	}

	if risk == "" {
		risk = domain.SeverityInfo
	}
	if len(findings) > 0 && verdict == domain.GatewayAllow {
		verdict = domain.GatewayRequireApproval
	}
	if history.ApprovalCount > 0 && verdict == domain.GatewayAllow {
		findings = append(findings, fmt.Sprintf("history_prior_approvals=%d", history.ApprovalCount))
	}
	return verdict, reason, risk, findings
}

func (e *Engine) scoreGatewayRequest(request domain.ToolCallRequest, tool string, command string, signal string, alerts []domain.Alert, taint TaintAnalysis, history gatewayHistorySnapshot, verdict domain.GatewayVerdict, risk domain.Severity) (int, []string) {
	score := risk.Rank() * 10
	factors := []string{fmt.Sprintf("risk=%s", risk), fmt.Sprintf("verdict=%s", verdict)}

	if len(alerts) > 0 {
		score += severityForAlerts(alerts).Rank() * 8
		factors = append(factors, fmt.Sprintf("alerts=%d", len(alerts)))
	}
	if taint.HasSourcePrefix("secret:") {
		score += 20
		factors = append(factors, "taint:secret_source")
	}
	if taint.HasSourcePrefix("canary:") {
		score += 35
		factors = append(factors, "taint:canary_source")
	}
	if taint.HasSinkPrefix("external_destination:") {
		score += 15
		factors = append(factors, "taint:external_sink")
	}
	if taint.HasSignalPrefix("obfuscated_source:") || taint.HasSignalPrefix("obfuscated_sink:") {
		score += 10
		factors = append(factors, "taint:obfuscated")
	}
	if match, term, variant := gatewayContainsAny(gatewayTextVariants(command, signal, request.Destination, strings.Join(request.Labels, " "), metadataText(request.Metadata)), injectionTerms()); match {
		score += 18
		if variant != term {
			factors = append(factors, "injection:obfuscated")
		} else {
			factors = append(factors, "injection:keyword")
		}
	}
	if history.Calls > 0 {
		score += minInt(history.Calls*2, 12)
		factors = append(factors, fmt.Sprintf("history:calls=%d", history.Calls))
	}
	if history.ApprovalCount > 0 {
		score += minInt(history.ApprovalCount*8, 24)
		factors = append(factors, fmt.Sprintf("history:approvals=%d", history.ApprovalCount))
	}
	if history.DenyCount > 0 {
		score += minInt(history.DenyCount*10, 30)
		factors = append(factors, fmt.Sprintf("history:denies=%d", history.DenyCount))
	}
	if history.RiskScoreMax > 0 {
		score += minInt(history.RiskScoreMax/4, 20)
		factors = append(factors, fmt.Sprintf("history:max_risk=%d", history.RiskScoreMax))
	}
	if strings.TrimSpace(request.Destination) != "" {
		score += 5
		factors = append(factors, "context:destination")
	}
	if tool == "unknown" {
		score += 10
		factors = append(factors, "tool:unknown")
	}
	if len(request.Labels) > 0 {
		score += minInt(len(request.Labels)*2, 8)
		factors = append(factors, fmt.Sprintf("context:labels=%d", len(request.Labels)))
	}
	if len(factors) > 10 {
		factors = factors[len(factors)-10:]
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, factors
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

func injectionTerms() []string {
	return []string{
		"ignore previous",
		"system prompt",
		"developer message",
		"prompt injection",
		"jailbreak",
		"bypass policy",
		"reveal prompt",
		"tool schema",
		"curl | sh",
		"base64 -d",
		"powershell -enc",
		"invoke-expression",
		"eval(",
		"cmd /c",
	}
}

// lateralMovementTerms flags remote-execution / lateral-movement tooling
// (MITRE ATT&CK TA0008, e.g. T1021). These are high-signal indicators that an
// agent is trying to reach another host rather than act locally.
func lateralMovementTerms() []string {
	return []string{
		"psexec",
		"wmic /node",
		"enter-pssession",
		"invoke-command",
		"new-pssession",
		"wmiexec",
		"smbexec",
		"winrm",
		"mstsc",
		"schtasks /s",
	}
}

// impactTerms flags destructive / recovery-inhibiting actions (MITRE ATT&CK
// TA0040, e.g. T1486 data-encrypted-for-impact and T1490 inhibit-recovery).
// These should never run unattended, so they are gated for operator approval.
func impactTerms() []string {
	return []string{
		"vssadmin delete",
		"delete shadows",
		"shadowcopy delete",
		"wbadmin delete",
		"bcdedit",
		"cipher /w",
		"ransom",
		".locked",
		".encrypted",
		"encrypt all files",
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
	// Decode up to a bounded depth so multi-layer encodings (e.g. base64 of
	// base64, or base64 of hex) cannot evade the obfuscation matcher with one
	// extra wrapper. Depth is bounded to keep the gateway hot path cheap.
	return decodeGatewayCandidatesDepth(token, 3)
}

func decodeGatewayCandidatesDepth(token string, depth int) []string {
	if depth <= 0 {
		return nil
	}
	var candidates []string
	add := func(decoded []byte) {
		// Keep case for the recursion (an inner base64/hex layer is case- or
		// nibble-sensitive) but emit the normalized form for matching.
		raw := printableGatewayBytes(decoded)
		if strings.TrimSpace(raw) == "" || raw == token {
			return
		}
		if normalized := normalizeGatewayText(raw); normalized != "" {
			candidates = append(candidates, normalized)
		}
		candidates = append(candidates, decodeGatewayCandidatesDepth(raw, depth-1)...)
	}
	if looksBase64Like(token) {
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			if decoded, err := encoding.DecodeString(padBase64(token)); err == nil {
				add(decoded)
			}
		}
	}
	if looksHexLike(token) {
		if decoded, err := hex.DecodeString(token); err == nil {
			add(decoded)
		}
	}
	return candidates
}

func looksHexLike(token string) bool {
	if len(token) < 8 || len(token)%2 != 0 {
		return false
	}
	for _, r := range token {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
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

// printableGatewayBytes keeps only printable runes but preserves case, so a
// decoded layer that is itself an encoded string can be decoded again.
func printableGatewayBytes(decoded []byte) string {
	if len(decoded) == 0 {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, string(decoded))
}

func printableGatewayText(decoded []byte) string {
	return normalizeGatewayText(printableGatewayBytes(decoded))
}
