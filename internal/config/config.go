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
	ApprovedTools       []string          `json:"approved_tools"`
	ApprovedEgressHosts []string          `json:"approved_egress_hosts"`
	CorrelationWindow   string            `json:"correlation_window"`
	Users               []auth.UserConfig `json:"users"`
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

func (c Config) PolicyConfig() policy.Config {
	return policy.Config{
		ApprovedTools:       c.ApprovedTools,
		ApprovedEgressHosts: c.ApprovedEgressHosts,
	}
}

func (c Config) CorrelationWindowDuration() (time.Duration, error) {
	if c.CorrelationWindow == "" {
		return DefaultCorrelationWindow, nil
	}
	return time.ParseDuration(c.CorrelationWindow)
}
