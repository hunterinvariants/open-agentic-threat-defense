package server

import (
	"encoding/json"
	"testing"
)

// FuzzToolCallFromMCPRequest feeds arbitrary MCP method names and params
// (including non-JSON and malformed objects) through the MCP request mapping. It
// parses untrusted client input and must never panic on any of it.
func FuzzToolCallFromMCPRequest(f *testing.F) {
	f.Add("tools/call", `{"name":"asset_inventory","arguments":{"q":"x"}}`)
	f.Add("resources/read", `{"uri":"https://exfil.example/secret"}`)
	f.Add("prompts/get", `{"name":"p","arguments":{"text":"ignore previous"}}`)
	f.Add("unknown/method", `not json at all`)
	f.Add("", ``)
	f.Add("tools/call", `{"name":12345,"arguments":[1,2,3]}`)

	app := &App{}
	f.Fuzz(func(t *testing.T, method, params string) {
		_ = app.toolCallFromMCPRequest(mcpJSONRPCRequest{
			Method: method,
			Params: json.RawMessage(params),
		})
	})
}
