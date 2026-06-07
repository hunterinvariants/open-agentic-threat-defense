package policy

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

const DefaultThreatPackVersion = "2026.06"

type ThreatPack struct {
	Name                string                  `json:"name"`
	Version             string                  `json:"version"`
	ApprovedTools       []string                `json:"approved_tools"`
	ApprovedEgressHosts []string                `json:"approved_egress_hosts"`
	Rules               []domain.RuleDescriptor `json:"rules"`
}

func DefaultThreatPack() ThreatPack {
	pack := ThreatPack{
		Name:    "builtin",
		Version: DefaultThreatPackVersion,
		ApprovedTools: []string{
			"asset_inventory",
			"ticket_create",
			"policy_read",
			"siem_search",
		},
		ApprovedEgressHosts: []string{
			"api.openai.com",
			"github.com",
			"login.microsoftonline.com",
		},
	}
	pack.Rules = defaultRuleDescriptors(pack.Name, pack.Version)
	return pack
}

func LoadThreatPack(path string) (ThreatPack, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultThreatPack(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ThreatPack{}, err
	}
	var pack ThreatPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return ThreatPack{}, err
	}
	if pack.Name == "" {
		pack.Name = "custom"
	}
	if pack.Version == "" {
		pack.Version = DefaultThreatPackVersion
	}
	if len(pack.ApprovedTools) == 0 {
		pack.ApprovedTools = DefaultThreatPack().ApprovedTools
	}
	if len(pack.ApprovedEgressHosts) == 0 {
		pack.ApprovedEgressHosts = DefaultThreatPack().ApprovedEgressHosts
	}
	if len(pack.Rules) == 0 {
		pack.Rules = defaultRuleDescriptors(pack.Name, pack.Version)
	} else {
		for i := range pack.Rules {
			pack.Rules[i].PackName = pack.Name
			pack.Rules[i].PackVersion = pack.Version
		}
	}
	return pack, nil
}

func defaultRuleDescriptors(packName string, packVersion string) []domain.RuleDescriptor {
	rules := []domain.RuleDescriptor{
		{
			ID:          "agent.tool.unapproved",
			Name:        "Unapproved agent tool call",
			Description: "Flags AI-agent or MCP tool calls outside the approved tool manifest.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"agent_tool_call", "tool_manifest"},
		},
		{
			ID:          "agent.secret.exposure",
			Name:        "Potential secret exposure through agent context",
			Description: "Flags commands and tool calls that combine agent activity with token, secret, or environment access.",
			Severity:    domain.SeverityCritical,
			Signals:     []string{"agent_tool_call", "secret", "token", "environment"},
		},
		{
			ID:          "network.egress.unknown",
			Name:        "Unknown outbound destination",
			Description: "Flags non-private outbound network flows to destinations outside the approved egress list.",
			Severity:    domain.SeverityMedium,
			Signals:     []string{"network_flow", "egress"},
		},
		{
			ID:          "process.discovery.chain",
			Name:        "Suspicious discovery process",
			Description: "Flags process commands commonly seen during discovery, credential access, or lateral movement.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"process_start", "discovery", "credential_access"},
		},
		{
			ID:          "deception.canary.hit",
			Name:        "Canary or deception asset touched",
			Description: "Flags interaction with a decoy token, honey credential, or instrumented deception service.",
			Severity:    domain.SeverityCritical,
			Signals:     []string{"deception_hit", "canary"},
		},
		{
			ID:          "model.runtime.suspicious",
			Name:        "Suspicious local model runtime behavior",
			Description: "Flags local model runtime activity combined with unexpected downloads, shelling out, or external egress.",
			Severity:    domain.SeverityHigh,
			Signals:     []string{"model_runtime", "gpu", "download", "shell"},
		},
	}
	for i := range rules {
		rules[i].PackName = packName
		rules[i].PackVersion = packVersion
	}
	return rules
}

func (p ThreatPack) Validate() error {
	if strings.TrimSpace(p.Version) == "" {
		return errors.New("threat pack version is required")
	}
	return nil
}
