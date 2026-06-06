package exporter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestWebhookExportsAlerts(t *testing.T) {
	var got AlertPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing authorization header")
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	webhook := Webhook{URL: server.URL, Token: "token", Client: server.Client()}
	err := webhook.ExportAlerts([]domain.Alert{{ID: "alert-1", Title: "test"}})
	if err != nil {
		t.Fatalf("export alerts: %v", err)
	}
	if got.Type != "oadtd.alerts" || len(got.Alerts) != 1 {
		t.Fatalf("unexpected payload: %#v", got)
	}
}
