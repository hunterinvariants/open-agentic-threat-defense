package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
	"github.com/open-agentic-threat-defense/oadtd/internal/policy"
)

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	body := `{
  "approved_tools": ["asset_inventory", "shell_exec"],
  "approved_egress_hosts": ["example.com"],
  "correlation_window": "45m",
  "users": [{"name":"alice","token_sha256":"hash","roles":["operator"]}]
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
	if len(loaded.Users) != 1 || loaded.Users[0].Name != "alice" {
		t.Fatalf("unexpected users: %#v", loaded.Users)
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

func TestPolicyConfigAppliesApprovedTools(t *testing.T) {
	cfg := Config{ApprovedTools: []string{"custom_tool"}}
	pc, err := cfg.PolicyConfig()
	if err != nil {
		t.Fatal(err)
	}
	engine := policy.New(pc)

	// A tool declared in policy.json must be approved (not denied as unapproved).
	allowed := engine.GateToolCall(domain.ToolCallRequest{
		ID: "c1", AssetID: "h", Actor: "a", ToolName: "custom_tool", Command: "list",
	})
	if allowed.Verdict == domain.GatewayDeny {
		t.Fatalf("custom approved tool should not be denied, got %s (%s)", allowed.Verdict, allowed.Reason)
	}

	// A default tool absent from policy.json must now be unapproved: the list is
	// authoritative (regression guard for the propagation fix).
	denied := engine.GateToolCall(domain.ToolCallRequest{
		ID: "c2", AssetID: "h", Actor: "a", ToolName: "ticket_create", Command: "open",
	})
	if denied.Verdict != domain.GatewayDeny {
		t.Fatalf("tool absent from policy.json approved_tools should be denied, got %s", denied.Verdict)
	}
}
