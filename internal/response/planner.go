package response

import (
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type Planner struct {
	Mode string
}

func NewDryRun() *Planner {
	return &Planner{Mode: "dry-run"}
}

func (p *Planner) Plan(alert domain.Alert) []domain.ResponseAction {
	mode := p.Mode
	if mode == "" {
		mode = "dry-run"
	}

	actions := []domain.ResponseAction{
		{
			Type:    "create_incident_ticket",
			Mode:    mode,
			AssetID: alert.AssetID,
			Target:  alert.ID,
			Reason:  "Create an audit trail and assign incident ownership.",
		},
	}

	if alert.Severity.Rank() >= domain.SeverityHigh.Rank() {
		actions = append(actions, domain.ResponseAction{
			Type:    "isolate_host",
			Mode:    mode,
			AssetID: alert.AssetID,
			Target:  alert.AssetID,
			Reason:  "Contain high-severity activity before lateral movement expands.",
		})
	}

	if strings.Contains(alert.RuleID, "egress") || strings.Contains(alert.RuleID, "sequence") || strings.Contains(alert.RuleID, "model.runtime") {
		actions = append(actions, domain.ResponseAction{
			Type:    "block_egress",
			Mode:    mode,
			AssetID: alert.AssetID,
			Target:  firstNonEmpty(alert.Evidence["destination"], alert.Evidence["egress_event"], "unknown"),
			Reason:  "Stop unexpected external communication while preserving evidence.",
		})
	}

	if strings.Contains(alert.RuleID, "agent.tool") {
		actions = append(actions, domain.ResponseAction{
			Type:    "disable_agent_tool",
			Mode:    mode,
			AssetID: alert.AssetID,
			Target:  firstNonEmpty(alert.Evidence["tool"], "unknown"),
			Reason:  "Remove unapproved tool access from the agent runtime.",
		})
	}

	if strings.Contains(alert.RuleID, "secret") || strings.Contains(alert.RuleID, "canary") || strings.Contains(alert.RuleID, "deception") {
		actions = append(actions, domain.ResponseAction{
			Type:    "rotate_related_secrets",
			Mode:    mode,
			AssetID: alert.AssetID,
			Target:  alert.AssetID,
			Reason:  "Invalidate credentials that may have been exposed or touched.",
		})
	}

	return actions
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
