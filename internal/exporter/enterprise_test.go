package exporter

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func sampleAction() domain.ResponseAction {
	return domain.ResponseAction{
		ID:       "act-1",
		Type:     "create_incident_ticket",
		AssetID:  "host-1",
		Reason:   "canary token touched",
		Metadata: map[string]string{"verdict": "deny", "risk": "critical"},
	}
}

func TestJiraCreateIncident(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"SEC-1"}`))
	}))
	defer srv.Close()

	j := Jira{BaseURL: srv.URL, Email: "a@b.c", APIToken: "tok", ProjectKey: "SEC", IssueType: "Bug"}
	if !j.Enabled() {
		t.Fatal("jira should be enabled")
	}
	if err := j.CreateIncident(sampleAction()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if gotPath != "/rest/api/2/issue" {
		t.Fatalf("path: %s", gotPath)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("a@b.c:tok"))
	if gotAuth != wantAuth {
		t.Fatalf("auth: %s", gotAuth)
	}
	if !strings.Contains(gotBody, `"key":"SEC"`) || !strings.Contains(gotBody, "canary token touched") || !strings.Contains(gotBody, `"name":"Bug"`) {
		t.Fatalf("body: %s", gotBody)
	}
}

func TestServiceNowCreateIncident(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"result":{"number":"INC001"}}`))
	}))
	defer srv.Close()

	s := ServiceNow{InstanceURL: srv.URL, User: "u", Password: "p"}
	if !s.Enabled() {
		t.Fatal("servicenow should be enabled")
	}
	if err := s.CreateIncident(sampleAction()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if gotPath != "/api/now/table/incident" {
		t.Fatalf("path: %s", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("auth: %s", gotAuth)
	}
	if !strings.Contains(gotBody, "short_description") || !strings.Contains(gotBody, "canary token touched") {
		t.Fatalf("body: %s", gotBody)
	}
}

func TestEnterpriseConnectorsDisabledWhenUnconfigured(t *testing.T) {
	if (Jira{}).Enabled() {
		t.Fatal("empty jira must be disabled")
	}
	if (ServiceNow{}).Enabled() {
		t.Fatal("empty servicenow must be disabled")
	}
	// Disabled connectors are a no-op, not an error.
	if err := (Jira{}).CreateIncident(sampleAction()); err != nil {
		t.Fatalf("disabled jira should no-op: %v", err)
	}
	if err := (ServiceNow{}).CreateIncident(sampleAction()); err != nil {
		t.Fatalf("disabled servicenow should no-op: %v", err)
	}
}
