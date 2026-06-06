package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunProcessesTailAndPersistsState(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode events: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "sysmon.jsonl")
	statePath := filepath.Join(dir, "agent-state.json")
	if err := os.WriteFile(logPath, []byte(`{"EventID":"1","Computer":"host-1","UtcTime":"2026-06-06T10:00:00Z","EventData":{"Image":"cmd.exe","CommandLine":"whoami"}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	if err := Run(context.Background(), Config{
		Source:       "sysmon-json",
		Path:         logPath,
		BaseURL:      server.URL,
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		StatePath:    statePath,
		Once:         true,
		Client:       server.Client(),
	}); err != nil {
		t.Fatalf("run agent: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected one batch, got %#v", got)
	}
	if got[0]["kind"] != "process_start" {
		t.Fatalf("unexpected event payload: %#v", got[0])
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if !strings.Contains(string(stateData), `"offset"`) {
		t.Fatalf("expected state file contents, got %s", string(stateData))
	}
}

func TestParseWindowsEventLog(t *testing.T) {
	output := []byte(`{"RecordId":42,"EventId":4688,"ProviderName":"Microsoft-Windows-Security-Auditing","MachineName":"host-1","TimeCreated":"2026-06-06T10:00:00Z","Message":"process created"}`)
	state := State{}
	events, err := parseWindowsEventLog(output, &state)
	if err != nil {
		t.Fatalf("parse windows event log: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "process_start" {
		t.Fatalf("unexpected events: %#v", events)
	}
	if state.RecordID != 42 {
		t.Fatalf("expected record id 42, got %d", state.RecordID)
	}
}

func TestParseJournalRecords(t *testing.T) {
	output := []byte(`{"__CURSOR":"cursor-1","__REALTIME_TIMESTAMP":"1760000000000000","_HOSTNAME":"host-1","_SYSTEMD_UNIT":"sshd.service","SYSLOG_IDENTIFIER":"sshd","PRIORITY":"4","MESSAGE":"Failed password for root"}`)
	state := State{}
	events, err := parseJournalRecords(output, &state)
	if err != nil {
		t.Fatalf("parse journal records: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "auth" {
		t.Fatalf("unexpected events: %#v", events)
	}
	if state.Cursor != "cursor-1" {
		t.Fatalf("expected cursor-1, got %s", state.Cursor)
	}
}

func TestRunRetriesTransientPostFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sysmon.jsonl")
	statePath := filepath.Join(dir, "agent-state.json")
	if err := os.WriteFile(logPath, []byte(`{"EventID":"1","Computer":"host-1","UtcTime":"2026-06-06T10:00:00Z","EventData":{"Image":"cmd.exe","CommandLine":"whoami"}}`+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var attempts int
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`temporary failure`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	err := Run(ctx, Config{
		Source:       "sysmon-json",
		Path:         logPath,
		BaseURL:      server.URL,
		BatchSize:    10,
		PollInterval: 10 * time.Millisecond,
		StatePath:    statePath,
		Client:       server.Client(),
	})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after retry loop, got %v", err)
	}
	if attempts < 2 {
		t.Fatalf("expected retry after failure, got %d attempts", attempts)
	}
}
