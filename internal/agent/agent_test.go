package agent

import (
	"context"
	"encoding/json"
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
