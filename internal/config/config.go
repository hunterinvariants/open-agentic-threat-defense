package config

import (
	"bytes"
	"encoding/json"
	"os"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/auth"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
)

const DefaultCorrelationWindow = 30 * time.Minute

type Config struct {
	ApprovedTools       []string                     `json:"approved_tools"`
	ApprovedEgressHosts []string                     `json:"approved_egress_hosts"`
	CorrelationWindow   string                       `json:"correlation_window"`
	ThreatPackPath      string                       `json:"threat_pack_path"`
	Users               []auth.UserConfig            `json:"users"`
	ToolProvenance      []policy.ToolProvenanceEntry `json:"tool_provenance,omitempty"`
}

func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) PolicyConfig() (policy.Config, error) {
	pack, err := policy.LoadThreatPack(c.ThreatPackPath)
	if err != nil {
		return policy.Config{}, err
	}
	if len(c.ApprovedTools) > 0 {
		pack.ApprovedTools = append([]string(nil), c.ApprovedTools...)
	}
	if len(c.ApprovedEgressHosts) > 0 {
		pack.ApprovedEgressHosts = append([]string(nil), c.ApprovedEgressHosts...)
	}
	return policy.Config{
		ApprovedTools:       append([]string(nil), c.ApprovedTools...),
		ApprovedEgressHosts: append([]string(nil), c.ApprovedEgressHosts...),
		ThreatPack:          pack,
		ToolProvenance:      append([]policy.ToolProvenanceEntry(nil), c.ToolProvenance...),
	}, nil
}

func (c Config) CorrelationWindowDuration() (time.Duration, error) {
	if c.CorrelationWindow == "" {
		return DefaultCorrelationWindow, nil
	}
	return time.ParseDuration(c.CorrelationWindow)
}
