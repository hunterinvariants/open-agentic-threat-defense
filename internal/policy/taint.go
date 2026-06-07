package policy

import (
	"fmt"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type TaintAnalysis struct {
	Sources    []string
	Sinks      []string
	Flows      []string
	Provenance []string
	Signals    []string
}

func (t TaintAnalysis) HasSourcePrefix(prefix string) bool {
	for _, value := range t.Sources {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func (t TaintAnalysis) HasSinkPrefix(prefix string) bool {
	for _, value := range t.Sinks {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func (t TaintAnalysis) HasSignalPrefix(prefix string) bool {
	for _, value := range t.Signals {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func analyzeGatewayTaint(request domain.ToolCallRequest, tool string, command string, signal string) TaintAnalysis {
	variationPool := gatewayTextVariants(
		command,
		request.Signal,
		request.Destination,
		strings.Join(request.Labels, " "),
		metadataText(request.Metadata),
		request.Actor,
		request.Hostname,
		tool,
	)

	analysis := TaintAnalysis{
		Provenance: collectGatewayProvenance(request),
	}

	for _, term := range taintSourceTerms() {
		if match, matched, variant := gatewayContainsAny(variationPool, []string{term}); match {
			source := fmt.Sprintf("%s:%s", classifyTaintSource(term), matched)
			analysis.Sources = appendUniqueString(analysis.Sources, source)
			analysis.Provenance = appendUniqueString(analysis.Provenance, fmt.Sprintf("source_variant:%s", variant))
			if variant != term {
				analysis.Signals = appendUniqueString(analysis.Signals, fmt.Sprintf("obfuscated_source:%s", matched))
			}
		}
	}

	if request.Destination != "" {
		if isExternalDestination(request.Destination) {
			analysis.Sinks = appendUniqueString(analysis.Sinks, "external_destination:"+normalizeHost(request.Destination))
		}
		if sink := taintSinkFromDestination(request.Destination); sink != "" {
			analysis.Sinks = appendUniqueString(analysis.Sinks, sink)
		}
	}

	for _, term := range taintSinkTerms() {
		if match, matched, variant := gatewayContainsAny(variationPool, []string{term}); match {
			sink := fmt.Sprintf("sink:%s", matched)
			analysis.Sinks = appendUniqueString(analysis.Sinks, sink)
			analysis.Provenance = appendUniqueString(analysis.Provenance, fmt.Sprintf("sink_variant:%s", variant))
			if variant != term {
				analysis.Signals = appendUniqueString(analysis.Signals, fmt.Sprintf("obfuscated_sink:%s", matched))
			}
		}
	}

	if len(analysis.Sources) > 0 && len(analysis.Sinks) > 0 {
		for _, source := range analysis.Sources {
			for _, sink := range analysis.Sinks {
				analysis.Flows = appendUniqueString(analysis.Flows, source+"->"+sink)
			}
		}
	}

	return analysis
}

func collectGatewayProvenance(request domain.ToolCallRequest) []string {
	provenance := []string{}
	appendField := func(key, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			provenance = appendUniqueString(provenance, key+":"+value)
		}
	}
	appendField("asset", request.AssetID)
	appendField("host", request.Hostname)
	appendField("actor", request.Actor)
	appendField("request", request.ID)
	for _, key := range []string{"session_id", "conversation_id", "trace_id", "run_id", "agent_id"} {
		if value := strings.TrimSpace(request.Metadata[key]); value != "" {
			appendField(key, value)
		}
	}
	return provenance
}

func taintSourceTerms() []string {
	return []string{
		"canary",
		"honey",
		"decoy",
		"secret",
		"token",
		"credential",
		"password",
		"api_key",
		"ssh_key",
		"bearer",
		"env",
		"vault",
	}
}

func taintSinkTerms() []string {
	return []string{
		"webhook",
		"dispatch",
		"issue",
		"upload",
		"post",
		"send",
		"exfil",
		"github",
		"slack",
		"discord",
		"invoke-webrequest",
		"curl",
		"wget",
	}
}

func taintSinkFromDestination(destination string) string {
	host := normalizeHost(destination)
	if host == "" {
		return ""
	}
	if isExternalDestination(destination) {
		return "destination:" + host
	}
	return "destination:" + host
}

func classifyTaintSource(term string) string {
	switch term {
	case "canary", "honey", "decoy":
		return "canary"
	case "secret", "token", "credential", "password", "api_key", "ssh_key", "bearer", "env", "vault":
		return "secret"
	default:
		return "source"
	}
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
