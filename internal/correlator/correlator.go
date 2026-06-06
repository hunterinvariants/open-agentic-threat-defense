package correlator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Correlator struct {
	Window time.Duration
}

func New(window time.Duration) *Correlator {
	return &Correlator{Window: window}
}

func (c *Correlator) Evaluate(events []domain.Event) []domain.Alert {
	if c.Window == 0 {
		c.Window = 30 * time.Minute
	}

	byAsset := map[string][]domain.Event{}
	now := time.Now().UTC()
	for _, event := range events {
		if event.AssetID == "" {
			continue
		}
		if !event.Timestamp.IsZero() && event.Timestamp.Before(now.Add(-c.Window)) {
			continue
		}
		byAsset[event.AssetID] = append(byAsset[event.AssetID], event)
	}

	alerts := []domain.Alert{}
	for assetID, assetEvents := range byAsset {
		sort.Slice(assetEvents, func(i, j int) bool {
			return assetEvents[i].Timestamp.Before(assetEvents[j].Timestamp)
		})

		sequence := classifySequence(assetEvents)
		if sequence.discovery != "" && sequence.credential != "" && sequence.agentTool != "" && sequence.egress != "" {
			alerts = append(alerts, domain.Alert{
				Fingerprint: fmt.Sprintf("correlation.agentic.sequence:%s:%s", assetID, sequence.latest),
				RuleID:      "correlation.agentic.sequence",
				Title:       "Correlated agentic threat sequence",
				Description: "Discovery, credential-touch, agent-tool activity, and external egress appeared on the same asset inside the correlation window.",
				Severity:    domain.SeverityCritical,
				Status:      domain.AlertOpen,
				AssetID:     assetID,
				EventIDs:    sequence.eventIDs,
				Evidence: map[string]string{
					"discovery_event":  sequence.discovery,
					"credential_event": sequence.credential,
					"agent_tool_event": sequence.agentTool,
					"egress_event":     sequence.egress,
				},
			})
			continue
		}

		if sequence.discovery != "" && sequence.egress != "" {
			alerts = append(alerts, domain.Alert{
				Fingerprint: fmt.Sprintf("correlation.discovery.egress:%s:%s", assetID, sequence.latest),
				RuleID:      "correlation.discovery.egress",
				Title:       "Discovery followed by unexpected egress",
				Description: "Discovery-like process activity was followed by outbound network flow from the same asset.",
				Severity:    domain.SeverityHigh,
				Status:      domain.AlertOpen,
				AssetID:     assetID,
				EventIDs:    sequence.eventIDs,
				Evidence: map[string]string{
					"discovery_event": sequence.discovery,
					"egress_event":    sequence.egress,
				},
			})
		}
	}

	return alerts
}

type sequenceState struct {
	discovery  string
	credential string
	agentTool  string
	egress     string
	latest     string
	eventIDs   []string
}

func classifySequence(events []domain.Event) sequenceState {
	state := sequenceState{}
	for _, event := range events {
		if event.ID == "" {
			continue
		}
		text := strings.ToLower(strings.Join([]string{
			event.Signal,
			event.Command,
			event.Process,
			event.ToolName,
			strings.Join(event.Labels, " "),
		}, " "))

		if state.discovery == "" && containsAny(text, []string{"scan", "discovery", "whoami", "ipconfig", "ifconfig", "netstat", "arp -a", "nmap"}) {
			state.discovery = event.ID
			state.eventIDs = appendUnique(state.eventIDs, event.ID)
		}
		if state.credential == "" && containsAny(text, []string{"credential", "secret", "token", "password", "api_key", "ssh_key", "env"}) {
			state.credential = event.ID
			state.eventIDs = appendUnique(state.eventIDs, event.ID)
		}
		if state.agentTool == "" && event.Kind == domain.EventAgentToolCall {
			state.agentTool = event.ID
			state.eventIDs = appendUnique(state.eventIDs, event.ID)
		}
		if state.egress == "" && event.Kind == domain.EventNetworkFlow && event.Destination != "" {
			state.egress = event.ID
			state.eventIDs = appendUnique(state.eventIDs, event.ID)
		}
		state.latest = event.ID
	}
	return state
}

func containsAny(value string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
