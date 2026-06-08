package server

import (
	"encoding/json"
	"testing"
)

func TestMCPSurfaceClassification(t *testing.T) {
	cases := map[string]string{
		"tools/call":             "tool",
		"resources/read":         "resource",
		"resources/subscribe":    "resource",
		"prompts/get":            "prompt",
		"sampling/createMessage": "sampling",
		"completion/complete":    "completion",
		"some/unknown":           "other",
	}
	for method, want := range cases {
		if got := mcpSurface(method); got != want {
			t.Fatalf("mcpSurface(%q)=%q want %q", method, got, want)
		}
	}
}

func TestMCPPassthroughMethods(t *testing.T) {
	for _, m := range []string{"initialize", "ping", "tools/list", "resources/list", "resources/templates/list", "prompts/list", "roots/list", "notifications/cancelled"} {
		if !isMCPPassthroughMethod(m) {
			t.Fatalf("expected %q to pass through", m)
		}
	}
	for _, m := range []string{"tools/call", "resources/read", "prompts/get", "sampling/createMessage", "completion/complete", "some/unknown"} {
		if isMCPPassthroughMethod(m) {
			t.Fatalf("expected %q to be intercepted", m)
		}
	}
}

func TestToolCallFromMCPRequestSurfaces(t *testing.T) {
	app := &App{}

	// tools/call resolves the real tool name and is NOT a protocol surface.
	tc := app.toolCallFromMCPRequest(mcpJSONRPCRequest{
		Method: "tools/call",
		Params: json.RawMessage(`{"name":"siem_search","arguments":{"q":"x"}}`),
	})
	if tc.ToolName != "siem_search" {
		t.Fatalf("tools/call tool name = %q want siem_search", tc.ToolName)
	}
	if tc.ProtocolSurface {
		t.Fatal("tools/call must not be a protocol surface (allowlist applies)")
	}

	// resources/read of an external URI is a protocol surface and sets the
	// destination so egress detection applies.
	rr := app.toolCallFromMCPRequest(mcpJSONRPCRequest{
		Method: "resources/read",
		Params: json.RawMessage(`{"uri":"https://evil.example/secret"}`),
	})
	if !rr.ProtocolSurface {
		t.Fatal("resources/read must be a protocol surface")
	}
	if rr.Destination != "https://evil.example/secret" {
		t.Fatalf("resources/read external uri should set destination, got %q", rr.Destination)
	}
	if rr.Metadata["mcp_surface"] != "resource" {
		t.Fatalf("expected surface metadata 'resource', got %q", rr.Metadata["mcp_surface"])
	}
}
