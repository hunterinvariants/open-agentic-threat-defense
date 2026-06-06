package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestGitHubCreateIssue(t *testing.T) {
	var path string
	var got GitHubIssueRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode issue: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	gh := GitHub{
		BaseURL: server.URL,
		Owner:   "owner",
		Repo:    "repo",
		Token:   "token",
		Client:  server.Client(),
	}
	if err := gh.CreateIssue(domain.ResponseAction{ID: "act-1", Type: "create_incident_ticket", AssetID: "host-1", Target: "host-1", Reason: "containment"}); err != nil {
		t.Fatalf("create issue: %v", err)
	}
	if path != "/repos/owner/repo/issues" {
		t.Fatalf("unexpected path: %s", path)
	}
	if got.Title == "" || got.Body == "" {
		t.Fatalf("unexpected issue payload: %#v", got)
	}
}

func TestGitHubDispatchWorkflow(t *testing.T) {
	var path string
	var got GitHubWorkflowDispatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing auth header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode dispatch: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	gh := GitHub{
		BaseURL:      server.URL,
		Owner:        "owner",
		Repo:         "repo",
		Token:        "token",
		WorkflowFile: "runbook.yml",
		WorkflowRef:  "main",
		Client:       server.Client(),
	}
	if err := gh.DispatchWorkflow(domain.ResponseAction{ID: "act-1", Type: "isolate_host", AssetID: "host-1", Target: "host-1", Reason: "containment"}); err != nil {
		t.Fatalf("dispatch workflow: %v", err)
	}
	if path != "/repos/owner/repo/actions/workflows/runbook.yml/dispatches" {
		t.Fatalf("unexpected path: %s", path)
	}
	if got.Ref != "main" || got.Inputs["action_id"] != "act-1" {
		t.Fatalf("unexpected dispatch payload: %#v", got)
	}
}
