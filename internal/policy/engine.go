package policy

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Engine struct {
	cfgMu               sync.RWMutex
	approvedTools       map[string]struct{}
	approvedEgressHosts map[string]struct{}
	pack                ThreatPack
	historyMu           sync.Mutex
	history             map[string]*gatewayHistoryState
}

type Config struct {
	ApprovedTools       []string
	ApprovedEgressHosts []string
	ThreatPack          ThreatPack
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

	return &Engine{
		approvedTools:       approvedTools,
		approvedEgressHosts: approvedEgressHosts,
		pack:                pack,
		history:             make(map[string]*gatewayHistoryState),
	}
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

func (e *Engine) Evaluate(event domain.Event) []domain.Alert {
	alerts := []domain.Alert{}

	if event.Kind == domain.EventAgentToolCall {
		tool := strings.ToLower(strings.TrimSpace(event.ToolName))
		if tool == "" {
			tool = "unknown"
		}
		if !e.isToolApproved(tool) {
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

	if event.Kind == domain.EventNetworkFlow && isExternalDestination(event.Destination) && !e.isApprovedEgress(event.Destination) {
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
