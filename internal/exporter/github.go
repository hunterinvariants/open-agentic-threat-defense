package exporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type GitHub struct {
	BaseURL      string
	Owner        string
	Repo         string
	Token        string
	WorkflowFile string
	WorkflowRef  string
	Client       *http.Client
}

type GitHubIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

type GitHubWorkflowDispatchRequest struct {
	Ref    string            `json:"ref"`
	Inputs map[string]string `json:"inputs,omitempty"`
}

func (g GitHub) Enabled() bool {
	return g.Owner != "" && g.Repo != "" && g.Token != ""
}

func (g GitHub) CreateIssue(action domain.ResponseAction) error {
	if !g.Enabled() {
		return nil
	}
	endpoint := g.endpoint("/repos/%s/%s/issues", g.Owner, g.Repo)
	payload := GitHubIssueRequest{
		Title:  g.issueTitle(action),
		Body:   g.issueBody(action),
		Labels: []string{"oatd", "incident"},
	}
	return g.postJSON(endpoint, payload, http.StatusCreated)
}

func (g GitHub) DispatchWorkflow(action domain.ResponseAction) error {
	if !g.Enabled() || g.WorkflowFile == "" {
		return nil
	}
	endpoint := g.endpoint("/repos/%s/%s/actions/workflows/%s/dispatches", g.Owner, g.Repo, g.WorkflowFile)
	payload := GitHubWorkflowDispatchRequest{
		Ref: g.workflowRef(),
		Inputs: map[string]string{
			"action_id":   action.ID,
			"action_type": action.Type,
			"asset_id":    action.AssetID,
			"target":      action.Target,
			"reason":      action.Reason,
			"approved_by": action.ApprovedBy,
		},
	}
	return g.postJSON(endpoint, payload, http.StatusNoContent)
}

func (g GitHub) endpoint(format string, parts ...any) string {
	base := strings.TrimRight(g.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	return base + fmt.Sprintf(format, parts...)
}

func (g GitHub) workflowRef() string {
	if strings.TrimSpace(g.WorkflowRef) != "" {
		return strings.TrimSpace(g.WorkflowRef)
	}
	return "main"
}

func (g GitHub) issueTitle(action domain.ResponseAction) string {
	return fmt.Sprintf("OATD: %s on %s", action.Type, firstNonEmptyString(action.AssetID, action.Target, "unknown"))
}

func (g GitHub) issueBody(action domain.ResponseAction) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Response action `%s` was planned by OATD.\n\n", action.Type)
	fmt.Fprintf(&b, "- Asset: `%s`\n", action.AssetID)
	fmt.Fprintf(&b, "- Target: `%s`\n", action.Target)
	fmt.Fprintf(&b, "- Reason: %s\n", action.Reason)
	fmt.Fprintf(&b, "- Approval: `%s`\n", action.ApprovalStatus)
	if action.ApprovedBy != "" {
		fmt.Fprintf(&b, "- Approved by: `%s`\n", action.ApprovedBy)
	}
	if action.ExecutionStatus != "" {
		fmt.Fprintf(&b, "- Execution status: `%s`\n", action.ExecutionStatus)
	}
	if action.ExecutedAt != nil {
		fmt.Fprintf(&b, "- Executed at: `%s`\n", action.ExecutedAt.UTC().Format(time.RFC3339))
	}
	return b.String()
}

func (g GitHub) postJSON(endpoint string, payload any, expectedStatus int) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Content-Type", "application/json")

	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("github returned %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
