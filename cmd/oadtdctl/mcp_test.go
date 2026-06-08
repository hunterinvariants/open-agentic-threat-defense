package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestMCPVerdictFromStatus(t *testing.T) {
	cases := map[int]string{
		http.StatusOK:                 "forwarded",
		http.StatusCreated:            "forwarded",
		http.StatusAccepted:           "approval",
		http.StatusForbidden:          "blocked",
		http.StatusServiceUnavailable: "unavailable",
		http.StatusTeapot:             "http_418",
	}
	for code, want := range cases {
		if got := mcpVerdictFromStatus(code); got != want {
			t.Fatalf("mcpVerdictFromStatus(%d)=%q want %q", code, got, want)
		}
	}
}

func TestMCPDemoCasesWellFormed(t *testing.T) {
	cases := mcpDemoCases()
	if len(cases) < 5 {
		t.Fatalf("expected a meaningful demo, got %d", len(cases))
	}
	sawForwarded, sawBlocked, sawApproval := false, false, false
	for _, c := range cases {
		if c.name == "" || c.method == "" {
			t.Fatalf("case missing name/method: %+v", c)
		}
		switch c.want {
		case "forwarded":
			sawForwarded = true
		case "blocked":
			sawBlocked = true
		case "approval":
			sawApproval = true
		default:
			t.Fatalf("case %s has invalid want %q", c.name, c.want)
		}
	}
	if !sawForwarded || !sawBlocked || !sawApproval {
		t.Fatal("demo should exercise forwarded, approval, and blocked verdicts")
	}
}

func TestMCPStubResult(t *testing.T) {
	initResult, _ := mcpStubResult(stubRPCRequest{Method: "initialize"}).(map[string]any)
	if initResult["protocolVersion"] == nil {
		t.Fatal("initialize should return a protocolVersion")
	}

	call := mcpStubResult(stubRPCRequest{Method: "tools/call", Params: json.RawMessage(`{"name":"siem_search"}`)})
	cm, _ := call.(map[string]any)
	content, ok := cm["content"].([]map[string]any)
	if !ok || len(content) == 0 {
		t.Fatalf("tools/call should return content, got %#v", call)
	}
}
