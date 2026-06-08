package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestVerdictRankOrdering(t *testing.T) {
	if !(verdictRank(domain.GatewayDeny) > verdictRank(domain.GatewayRequireApproval) &&
		verdictRank(domain.GatewayRequireApproval) > verdictRank(domain.GatewayAllow)) {
		t.Fatal("verdict rank must order deny > require_approval > allow")
	}
}

func TestValidationCasesWellFormed(t *testing.T) {
	cases := validationCases("validation-agent")
	if len(cases) < 8 {
		t.Fatalf("expected a meaningful emulation library, got %d", len(cases))
	}
	sawBenign := false
	names := make(map[string]bool, len(cases))
	for _, c := range cases {
		if c.name == "" || c.technique == "" || c.tactic == "" {
			t.Fatalf("case missing name/technique/tactic: %+v", c)
		}
		if names[c.name] {
			t.Fatalf("duplicate case name %q", c.name)
		}
		names[c.name] = true
		switch c.want {
		case domain.GatewayAllow, domain.GatewayRequireApproval, domain.GatewayDeny:
		default:
			t.Fatalf("case %s has invalid want verdict %q", c.name, c.want)
		}
		if c.req.ToolName == "" {
			t.Fatalf("case %s has an empty tool name", c.name)
		}
		if c.want == domain.GatewayAllow {
			sawBenign = true
			if c.atLeast {
				t.Fatalf("benign case %s must be an exact match (atLeast=false)", c.name)
			}
		}
	}
	if !sawBenign {
		t.Fatal("the suite must include a benign baseline to catch false positives")
	}
}

func TestWaitForReadyReturnsWhenReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	done := make(chan struct{})
	go func() {
		waitForReady(srv.Client(), srv.URL, 5*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("waitForReady did not return promptly when the server is ready")
	}
}

func TestAppendHistoryAccumulates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	for i := 0; i < 3; i++ {
		if err := appendHistory(path, validationResult{Total: 3, Passed: 3 - i, Missed: i}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, line := range splitNonEmptyLines(string(data)) {
		var e historyEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("history line is not valid JSON: %v", err)
		}
		if e.Total != 3 || e.Time == "" {
			t.Fatalf("unexpected history entry: %+v", e)
		}
		lines++
	}
	if lines != 3 {
		t.Fatalf("expected 3 appended history lines, got %d", lines)
	}
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func TestWriteResultFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	res := validationResult{
		Total: 2, Passed: 1, Missed: 1,
		Rows: []resultRow{{Name: "x", Technique: "T1", Tactic: "Execution", Want: "allow", Got: "deny", Pass: false}},
	}
	if err := writeResultFile(path, res); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got validationResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got.Total != 2 || got.Passed != 1 || len(got.Rows) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should have been renamed away")
	}
}
