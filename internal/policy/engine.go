package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Engine struct {
	cfgMu               sync.RWMutex
	approvedTools       map[string]struct{}
	approvedEgressHosts map[string]struct{}
	pack                ThreatPack
	deceptionMu         sync.RWMutex
	deception           map[string]domain.DeceptionToken
	deceptionSeq        int
	tenantMu            sync.RWMutex
	tenantPolicies      map[string]compiledTenantPolicy
	historyMu           sync.Mutex
	history             map[string]*gatewayHistoryState
}

type Config struct {
	ApprovedTools       []string
	ApprovedEgressHosts []string
	ThreatPack          ThreatPack
	DeceptionTokens     []domain.DeceptionToken
}

func DefaultConfig() Config {
	pack := DefaultThreatPack()
	return Config{
		ApprovedTools:       append([]string(nil), pack.ApprovedTools...),
		ApprovedEgressHosts: append([]string(nil), pack.ApprovedEgressHosts...),
		ThreatPack:          pack,
	}
}

func NewDefault() *Engine {
	return New(DefaultConfig())
}

func New(config Config) *Engine {
	config = withDefaults(config)
	approvedTools := make(map[string]struct{}, len(config.ApprovedTools))
	for _, tool := range config.ApprovedTools {
		tool = strings.ToLower(strings.TrimSpace(tool))
		if tool != "" {
			approvedTools[tool] = struct{}{}
		}
	}
	approvedEgressHosts := make(map[string]struct{}, len(config.ApprovedEgressHosts))
	for _, host := range config.ApprovedEgressHosts {
		host = normalizeHost(host)
		if host != "" {
			approvedEgressHosts[host] = struct{}{}
		}
	}
	pack := config.ThreatPack
	if err := pack.Validate(); err != nil {
		pack = DefaultThreatPack()
	}
	if len(pack.ApprovedTools) == 0 {
		pack.ApprovedTools = append([]string(nil), config.ApprovedTools...)
	}
	if len(pack.ApprovedEgressHosts) == 0 {
		pack.ApprovedEgressHosts = append([]string(nil), config.ApprovedEgressHosts...)
	}
	if len(pack.Rules) == 0 {
		pack.Rules = defaultRuleDescriptors(pack.Name, pack.Version)
	}
	for i := range pack.Rules {
		if pack.Rules[i].PackName == "" {
			pack.Rules[i].PackName = pack.Name
		}
		if pack.Rules[i].PackVersion == "" {
			pack.Rules[i].PackVersion = pack.Version
		}
	}

	engine := &Engine{
		approvedTools:       approvedTools,
		approvedEgressHosts: approvedEgressHosts,
		pack:                pack,
		deception:           make(map[string]domain.DeceptionToken),
		tenantPolicies:      make(map[string]compiledTenantPolicy),
		history:             make(map[string]*gatewayHistoryState),
	}
	engine.SetDeceptionTokens(config.DeceptionTokens)
	return engine
}

func withDefaults(config Config) Config {
	defaults := DefaultConfig()
	if len(config.ApprovedTools) == 0 {
		config.ApprovedTools = defaults.ApprovedTools
	}
	if len(config.ApprovedEgressHosts) == 0 {
		config.ApprovedEgressHosts = defaults.ApprovedEgressHosts
	}
	if config.ThreatPack.Version == "" {
		config.ThreatPack = defaults.ThreatPack
	}
	return config
}

func (e *Engine) Rules() []domain.RuleDescriptor {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	return append([]domain.RuleDescriptor(nil), e.pack.Rules...)
}

func (e *Engine) isToolApproved(tool string) bool {
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	_, ok := e.approvedTools[tool]
	return ok
}

// Reload atomically swaps the detection configuration (approved tools, egress
// hosts, and threat pack) without a restart. Gateway call history is preserved.
func (e *Engine) Reload(config Config) {
	rebuilt := New(config)
	e.cfgMu.Lock()
	e.approvedTools = rebuilt.approvedTools
	e.approvedEgressHosts = rebuilt.approvedEgressHosts
	e.pack = rebuilt.pack
	e.cfgMu.Unlock()
}

// SetDeceptionTokens replaces the deception/canary registry (startup seed).
func (e *Engine) SetDeceptionTokens(tokens []domain.DeceptionToken) {
	e.deceptionMu.Lock()
	defer e.deceptionMu.Unlock()
	e.deception = make(map[string]domain.DeceptionToken, len(tokens))
	e.deceptionSeq = 0
	for _, token := range tokens {
		token = normalizeDeceptionToken(token)
		if token.Value == "" {
			continue
		}
		if token.ID == "" {
			token.ID = e.nextDeceptionIDLocked()
		}
		e.deception[token.ID] = token
	}
}

// AddDeceptionToken registers a canary/decoy token at runtime.
func (e *Engine) AddDeceptionToken(token domain.DeceptionToken) (domain.DeceptionToken, error) {
	if strings.TrimSpace(token.Value) == "" {
		return domain.DeceptionToken{}, errors.New("deception token value is required")
	}
	e.deceptionMu.Lock()
	defer e.deceptionMu.Unlock()
	token = normalizeDeceptionToken(token)
	if token.ID == "" {
		token.ID = e.nextDeceptionIDLocked()
	}
	e.deception[token.ID] = token
	return token, nil
}

func (e *Engine) ListDeceptionTokens() []domain.DeceptionToken {
	e.deceptionMu.RLock()
	defer e.deceptionMu.RUnlock()
	tokens := make([]domain.DeceptionToken, 0, len(e.deception))
	for _, token := range e.deception {
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].ID < tokens[j].ID })
	return tokens
}

func (e *Engine) RemoveDeceptionToken(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	e.deceptionMu.Lock()
	defer e.deceptionMu.Unlock()
	if _, ok := e.deception[id]; !ok {
		return false
	}
	delete(e.deception, id)
	return true
}

// MatchDeception reports whether any of the given text fields contain a
// registered canary value, using the same obfuscation-resistant matching as
// the gateway (compaction + base64 decode).
func (e *Engine) MatchDeception(values ...string) (domain.DeceptionToken, bool) {
	e.deceptionMu.RLock()
	defer e.deceptionMu.RUnlock()
	if len(e.deception) == 0 {
		return domain.DeceptionToken{}, false
	}
	variants := gatewayTextVariants(values...)
	for _, token := range e.deception {
		needle := normalizeGatewayText(token.Value)
		if needle == "" {
			continue
		}
		for _, variant := range variants {
			if strings.Contains(variant, needle) {
				return token, true
			}
		}
	}
	return domain.DeceptionToken{}, false
}

func normalizeDeceptionToken(token domain.DeceptionToken) domain.DeceptionToken {
	token.ID = strings.TrimSpace(token.ID)
	token.Value = strings.TrimSpace(token.Value)
	token.Kind = strings.ToLower(strings.TrimSpace(token.Kind))
	if token.Kind == "" {
		token.Kind = "secret"
	}
	token.Name = strings.TrimSpace(token.Name)
	if token.Name == "" {
		token.Name = token.Kind + "-canary"
	}
	if token.CreatedAt.IsZero() {
		token.CreatedAt = time.Now().UTC()
	}
	return token
}

// nextDeceptionIDLocked returns a unique dt-N id. Caller must hold deceptionMu.
func (e *Engine) nextDeceptionIDLocked() string {
	for {
		e.deceptionSeq++
		id := fmt.Sprintf("dt-%d", e.deceptionSeq)
		if _, exists := e.deception[id]; !exists {
			return id
		}
	}
}

func (e *Engine) Evaluate(event domain.Event) []domain.Alert {
	alerts := []domain.Alert{}

	if event.Kind == domain.EventAgentToolCall {
		tool := strings.ToLower(strings.TrimSpace(event.ToolName))
		if tool == "" {
			tool = "unknown"
		}
		if !e.toolApprovedForTenant(event.Tenant, tool) {
			alerts = append(alerts, newAlert(
				"agent.tool.unapproved",
				"Unapproved agent tool call",
				fmt.Sprintf("Agent invoked tool %q outside the approved manifest.", tool),
				domain.SeverityHigh,
				event,
				map[string]string{"tool": tool, "actor": event.Actor},
			))
		}

		if match, term, _ := gatewayContainsAny(gatewayTextVariants(event.Command, event.Signal, tool, metadataText(event.Metadata)), []string{"secret", "token", "credential", "password", "env", "ssh_key", "api_key"}); match {
			alerts = append(alerts, newAlert(
				"agent.secret.exposure",
				"Potential secret exposure through agent context",
				"Agent activity referenced secrets, credentials, tokens, or environment material.",
				domain.SeverityCritical,
				event,
				map[string]string{"tool": tool, "command": event.Command, "match": term},
			))
		}
	}

	if event.Kind == domain.EventNetworkFlow && isExternalDestination(event.Destination) && !e.egressApprovedForTenant(event.Tenant, event.Destination) {
		alerts = append(alerts, newAlert(
			"network.egress.unknown",
			"Unknown outbound destination",
			"Asset opened outbound network flow to a non-private destination outside the approved egress list.",
			domain.SeverityMedium,
			event,
			map[string]string{"destination": event.Destination, "source_ip": event.SourceIP},
		))
	}

	if event.Kind == domain.EventProcessStart && func() bool {
		match, _, _ := gatewayContainsAny(gatewayTextVariants(event.Command, event.Process, event.Signal, metadataText(event.Metadata)), discoveryTerms())
		return match
	}() {
		alerts = append(alerts, newAlert(
			"process.discovery.chain",
			"Suspicious discovery process",
			"Process activity matched discovery, credential-access, or lateral-movement telemetry patterns.",
			domain.SeverityHigh,
			event,
			map[string]string{"process": event.Process, "command": event.Command},
		))
	}

	if event.Kind == domain.EventDeceptionHit || hasLabel(event.Labels, "canary") || hasLabel(event.Labels, "deception") {
		alerts = append(alerts, newAlert(
			"deception.canary.hit",
			"Canary or deception asset touched",
			"An asset interacted with a decoy token, honey credential, or instrumented deception service.",
			domain.SeverityCritical,
			event,
			map[string]string{"signal": event.Signal, "destination": event.Destination},
		))
	}

	if token, ok := e.MatchDeception(event.Command, event.Signal, event.ToolName, event.Destination, strings.Join(event.Labels, " "), metadataText(event.Metadata)); ok {
		alerts = append(alerts, newAlert(
			"deception.canary.hit",
			"Canary or deception asset touched",
			"Activity referenced a registered deception/canary token from the registry.",
			domain.SeverityCritical,
			event,
			map[string]string{"deception_token": token.Name, "deception_kind": token.Kind, "deception_id": token.ID},
		))
	}

	if func() bool {
		match, _, _ := gatewayContainsAny(gatewayTextVariants(event.Command, event.Process, event.Signal, strings.Join(event.Labels, " "), metadataText(event.Metadata)), []string{"llama", "ollama", "vllm", "gguf", "model-download", "cuda", "gpu", "tool_spawn"})
		return match
	}() &&
		(event.Kind == domain.EventProcessStart || event.Kind == domain.EventNetworkFlow || event.Kind == domain.EventAgentToolCall) {
		alerts = append(alerts, newAlert(
			"model.runtime.suspicious",
			"Suspicious local model runtime behavior",
			"Local model runtime activity appeared together with shelling out, downloads, GPU use, or unexpected egress.",
			domain.SeverityHigh,
			event,
			map[string]string{"process": event.Process, "destination": event.Destination},
		))
	}

	return alerts
}

func newAlert(ruleID, title, description string, severity domain.Severity, event domain.Event, evidence map[string]string) domain.Alert {
	return domain.Alert{
		Fingerprint: fmt.Sprintf("%s:%s", ruleID, event.ID),
		RuleID:      ruleID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      domain.AlertOpen,
		AssetID:     event.AssetID,
		EventIDs:    []string{event.ID},
		Evidence:    evidence,
	}
}

func (e *Engine) isApprovedEgress(destination string) bool {
	host := normalizeHost(destination)
	if host == "" {
		return false
	}
	e.cfgMu.RLock()
	defer e.cfgMu.RUnlock()
	_, ok := e.approvedEgressHosts[host]
	return ok
}

func normalizeHost(destination string) string {
	if destination == "" {
		return ""
	}

	if parsed, err := url.Parse(destination); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}

	host := destination
	if strings.Contains(host, "/") {
		host = strings.SplitN(host, "/", 2)[0]
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func isExternalDestination(destination string) bool {
	host := normalizeHost(destination)
	if host == "" {
		return false
	}
	if strings.HasSuffix(host, ".local") || host == "localhost" {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func containsAny(value string, needles []string) bool {
	value = strings.ToLower(value)
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func hasLabel(labels []string, label string) bool {
	for _, value := range labels {
		if strings.EqualFold(value, label) {
			return true
		}
	}
	return false
}

func discoveryTerms() []string {
	return []string{
		"whoami",
		"ipconfig",
		"ifconfig",
		"net user",
		"net group",
		"netstat",
		"arp -a",
		"nltest",
		"dsquery",
		"powershell",
		"invoke-webrequest",
		"curl",
		"wget",
		"nmap",
		"masscan",
		"credential",
		"token",
		"ssh_key",
	}
}
