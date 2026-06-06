package server

import (
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func DemoEvents(now time.Time) []domain.Event {
	return []domain.Event{
		{
			ID:        "demo-evt-1",
			Timestamp: now.Add(-18 * time.Minute),
			Kind:      domain.EventHostObservation,
			AssetID:   "win-finance-07",
			Hostname:  "win-finance-07",
			SourceIP:  "10.40.7.19",
			Signal:    "endpoint enrolled",
			Labels:    []string{"windows", "finance"},
			Metadata:  map[string]string{"os": "windows"},
		},
		{
			ID:        "demo-evt-2",
			Timestamp: now.Add(-14 * time.Minute),
			Kind:      domain.EventProcessStart,
			AssetID:   "win-finance-07",
			Hostname:  "win-finance-07",
			SourceIP:  "10.40.7.19",
			Process:   "powershell.exe",
			Command:   "whoami; ipconfig /all; netstat -ano",
			Signal:    "discovery sequence",
			Labels:    []string{"windows", "discovery"},
		},
		{
			ID:        "demo-evt-3",
			Timestamp: now.Add(-12 * time.Minute),
			Kind:      domain.EventAgentToolCall,
			AssetID:   "win-finance-07",
			Hostname:  "win-finance-07",
			Actor:     "local-agent",
			ToolName:  "shell_exec",
			Command:   "read env token for connector troubleshooting",
			Signal:    "agent tool referenced token material",
			Labels:    []string{"agent", "mcp", "credential"},
		},
		{
			ID:          "demo-evt-4",
			Timestamp:   now.Add(-10 * time.Minute),
			Kind:        domain.EventNetworkFlow,
			AssetID:     "win-finance-07",
			Hostname:    "win-finance-07",
			SourceIP:    "10.40.7.19",
			Destination: "203.0.113.77:443",
			Signal:      "new outbound flow after discovery",
			Labels:      []string{"egress"},
		},
		{
			ID:        "demo-evt-5",
			Timestamp: now.Add(-8 * time.Minute),
			Kind:      domain.EventHostObservation,
			AssetID:   "llm-build-02",
			Hostname:  "llm-build-02",
			SourceIP:  "10.40.9.21",
			Signal:    "local model runtime observed",
			Labels:    []string{"linux", "gpu", "model_runtime"},
			Metadata:  map[string]string{"os": "linux"},
		},
		{
			ID:          "demo-evt-6",
			Timestamp:   now.Add(-7 * time.Minute),
			Kind:        domain.EventNetworkFlow,
			AssetID:     "llm-build-02",
			Hostname:    "llm-build-02",
			SourceIP:    "10.40.9.21",
			Destination: "models.example.invalid:443",
			Process:     "ollama",
			Signal:      "model-download with gpu activity",
			Labels:      []string{"model-download", "gpu"},
		},
		{
			ID:          "demo-evt-7",
			Timestamp:   now.Add(-4 * time.Minute),
			Kind:        domain.EventDeceptionHit,
			AssetID:     "dev-agent-03",
			Hostname:    "dev-agent-03",
			SourceIP:    "10.40.4.44",
			Destination: "canary-token-vault",
			Signal:      "honey credential accessed by agent process",
			Labels:      []string{"deception", "canary", "agent"},
		},
	}
}
