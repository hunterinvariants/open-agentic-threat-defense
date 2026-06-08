package policy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	toolProvenance      map[string]ToolProvenanceEntry
	agentIdentities     map[string]AgentIdentity
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
	ToolProvenance      []ToolProvenanceEntry
	AgentIdentities     []AgentIdentity
}

// AgentIdentity registers a known agent and the SHA-256 of its identity token.
// When any identities are configured, the gateway attributes each tool call to a
// verified agent: an unknown agent or a bad/missing token is gated for approval,
// and a token that does not match a claimed agent id is denied as impersonation.
// Compute KeyHash with `oadtdctl token-hash`. Opt-in: with none configured,
// identity is not enforced.
type AgentIdentity struct {
	AgentID string `json:"agent_id"`
	KeyHash string `json:"key_sha256"`
}

// ToolProvenanceEntry declares the expected provenance of an agent tool: the
// publisher and a fingerprint (e.g. a sha256 of the tool's signed manifest or
// schema). When configured, the gateway verifies that a tool call carries a
// matching fingerprint, so a spoofed or tampered tool is caught even if its name
// is on the approved list. Entries are optional and opt-in per tool.
type ToolProvenanceEntry struct {
	Tool        string `json:"tool"`
	Publisher   string `json:"publisher,omitempty"`
	Fingerprint string `json:"fingerprint"`
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
	toolProvenance := make(map[string]ToolProvenanceEntry, len(config.ToolProvenance))
	for _, entry := range config.ToolProvenance {
		name := strings.ToLower(strings.TrimSpace(entry.Tool))
		if name == "" || strings.TrimSpace(entry.Fingerprint) == "" {
			continue
		}
		toolProvenance[name] = ToolProvenanceEntry{
			Tool:        name,
			Publisher:   strings.TrimSpace(entry.Publisher),
			Fingerprint: strings.TrimSpace(entry.Fingerprint),
		}
	}
	agentIdentities := make(map[string]AgentIdentity, len(config.AgentIdentities))
	for _, entry := range config.AgentIdentities {
		id := strings.ToLower(strings.TrimSpace(entry.AgentID))
		hash := strings.ToLower(strings.TrimSpace(entry.KeyHash))
		if id == "" || hash == "" {
			continue
		}
		agentIdentities[id] = AgentIdentity{AgentID: id, KeyHash: hash}
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
		toolProvenance:      toolProvenance,
		agentIdentities:     agentIdentities,
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

type provenanceStatus int

const (
	provenanceNotRequired provenanceStatus = iota // no provenance entry for this tool
	provenanceVerified                            // entry exists and the claim matches
	provenanceMissing                             // entry exists but the call carries no fingerprint
	provenanceMismatch                            // entry exists and the claim does not match
)

// checkToolProvenance verifies a tool call against the configured provenance for
// that tool. It is opt-in: tools without an entry return provenanceNotRequired,
// so existing behaviour is unchanged unless an operator declares provenance.
func (e *Engine) checkToolProvenance(tool string, request domain.ToolCallRequest) provenanceStatus {
	e.cfgMu.RLock()
	entry, ok := e.toolProvenance[tool]
	e.cfgMu.RUnlock()
	if !ok {
		return provenanceNotRequired
	}
	claimed := strings.TrimSpace(request.ToolFingerprint)
	if claimed == "" {
		return provenanceMissing
	}
	if !strings.EqualFold(claimed, entry.Fingerprint) {
		return provenanceMismatch
	}
	if entry.Publisher != "" && !strings.EqualFold(strings.TrimSpace(request.ToolPublisher), entry.Publisher) {
		return provenanceMismatch
	}
	return provenanceVerified
}

type agentIdentityStatus int

const (
	agentNotRequired  agentIdentityStatus = iota // no agent registry configured
	agentVerified                                // claimed agent id + token match a registered agent
	agentUnidentified                            // registry configured but no agent id claimed
	agentUnknown                                 // claimed agent id is not registered
	agentMismatch                                // claimed agent id is registered but the token is wrong
)

// checkAgentIdentity attributes a tool call to a verified agent. It is opt-in:
// with no registered identities it returns agentNotRequired and behaviour is
// unchanged. When identities are configured, a free-text actor is no longer
// trusted — the call must present a registered agent id and a token that hashes
// to that agent's KeyHash.
func (e *Engine) checkAgentIdentity(request domain.ToolCallRequest) agentIdentityStatus {
	e.cfgMu.RLock()
	count := len(e.agentIdentities)
	entry, ok := e.agentIdentities[strings.ToLower(strings.TrimSpace(request.AgentID))]
	e.cfgMu.RUnlock()
	if count == 0 {
		return agentNotRequired
	}
	if strings.TrimSpace(request.AgentID) == "" {
		return agentUnidentified
	}
	if !ok {
		return agentUnknown
	}
	if strings.TrimSpace(request.AgentToken) == "" {
		return agentMismatch
	}
	if subtle.ConstantTimeCompare([]byte(hashAgentToken(request.AgentToken)), []byte(entry.KeyHash)) != 1 {
		return agentMismatch
	}
	return agentVerified
}

func hashAgentToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

// Reload atomically swaps the detection configuration (approved tools, egress
// hosts, and threat pack) without a restart. Gateway call history is preserved.
func (e *Engine) Reload(config Config) {
	rebuilt := New(config)
	e.cfgMu.Lock()
	e.approvedTools = rebuilt.approvedTools
	e.toolProvenance = rebuilt.toolProvenance
	e.agentIdentities = rebuilt.agentIdentities
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
