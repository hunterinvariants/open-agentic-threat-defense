package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	body := `{
  "approved_tools": ["asset_inventory", "shell_exec"],
  "approved_egress_hosts": ["example.com"],
  "correlation_window": "45m"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loaded.ApprovedTools) != 2 {
		t.Fatalf("unexpected approved tool count: %d", len(loaded.ApprovedTools))
	}
	window, err := loaded.CorrelationWindowDuration()
	if err != nil {
		t.Fatalf("parse window: %v", err)
	}
	if window != 45*time.Minute {
		t.Fatalf("unexpected window: %s", window)
	}
}

func TestDefaultCorrelationWindow(t *testing.T) {
	loaded, err := Load("")
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	window, err := loaded.CorrelationWindowDuration()
	if err != nil {
		t.Fatalf("parse window: %v", err)
	}
	if window != DefaultCorrelationWindow {
		t.Fatalf("unexpected default window: %s", window)
	}
}
