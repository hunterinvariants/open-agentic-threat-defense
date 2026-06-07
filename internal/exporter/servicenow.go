package exporter

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// ServiceNow creates incidents in the ServiceNow incident table via the Table
// API (Basic auth).
type ServiceNow struct {
	InstanceURL string
	User        string
	Password    string
	Client      *http.Client
}

func (s ServiceNow) Enabled() bool {
	return strings.TrimSpace(s.InstanceURL) != "" &&
		strings.TrimSpace(s.User) != "" &&
		strings.TrimSpace(s.Password) != ""
}

func (s ServiceNow) CreateIncident(action domain.ResponseAction) error {
	if !s.Enabled() {
		return nil
	}
	payload := map[string]any{
		"short_description": ticketSummary(action),
		"description":       ticketDescription(action),
		"category":          "security",
		"u_source":          "open-agentic-threat-defense",
	}
	endpoint := strings.TrimRight(s.InstanceURL, "/") + "/api/now/table/incident"
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(s.User+":"+s.Password)),
		"Accept":        "application/json",
	}
	return postJSONTo(s.Client, endpoint, payload, headers, "servicenow")
}
