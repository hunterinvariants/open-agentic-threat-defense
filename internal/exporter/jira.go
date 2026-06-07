package exporter

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// Jira creates incidents as Jira issues via the REST API (Basic auth with an
// email + API token).
type Jira struct {
	BaseURL    string
	Email      string
	APIToken   string
	ProjectKey string
	IssueType  string
	Client     *http.Client
}

func (j Jira) Enabled() bool {
	return strings.TrimSpace(j.BaseURL) != "" &&
		strings.TrimSpace(j.ProjectKey) != "" &&
		strings.TrimSpace(j.Email) != "" &&
		strings.TrimSpace(j.APIToken) != ""
}

func (j Jira) CreateIncident(action domain.ResponseAction) error {
	if !j.Enabled() {
		return nil
	}
	issueType := strings.TrimSpace(j.IssueType)
	if issueType == "" {
		issueType = "Task"
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": j.ProjectKey},
			"summary":     ticketSummary(action),
			"description": ticketDescription(action),
			"issuetype":   map[string]string{"name": issueType},
		},
	}
	endpoint := strings.TrimRight(j.BaseURL, "/") + "/rest/api/2/issue"
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(j.Email+":"+j.APIToken)),
	}
	return postJSONTo(j.Client, endpoint, payload, headers, "jira")
}
