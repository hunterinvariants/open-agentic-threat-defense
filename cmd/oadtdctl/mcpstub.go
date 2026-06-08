package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// mcpStubCommand runs a minimal reference MCP server so the integration demo has
// a real upstream to route through the gateway proxy. It is a benign echo server
// — it executes nothing — and exists only to prove the end-to-end MCP path.
func mcpStubCommand(args []string) error {
	fs := flag.NewFlagSet("mcp-stub", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:9100", "address for the stub MCP server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleMCPStub)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("oadtdctl mcp-stub — reference MCP server on http://%s\n", *addr)
	return srv.ListenAndServe()
}

type stubRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func handleMCPStub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req stubRPCRequest
	_ = json.Unmarshal(body, &req)
	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": mcpStubResult(req)}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func mcpStubResult(req stubRPCRequest) any {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}},
			"serverInfo":      map[string]any{"name": "oadtd-mcp-stub", "version": "0.1.0"},
		}
	case "tools/list":
		return map[string]any{"tools": []map[string]any{
			{"name": "asset_inventory", "description": "list assets"},
			{"name": "siem_search", "description": "search the SIEM"},
		}}
	case "tools/call":
		var p map[string]any
		_ = json.Unmarshal(req.Params, &p)
		name, _ := p["name"].(string)
		return map[string]any{"content": []map[string]any{
			{"type": "text", "text": fmt.Sprintf("executed %s", name)},
		}}
	case "resources/read":
		var p map[string]any
		_ = json.Unmarshal(req.Params, &p)
		uri, _ := p["uri"].(string)
		return map[string]any{"contents": []map[string]any{
			{"uri": uri, "text": "resource-data"},
		}}
	case "ping":
		return map[string]any{}
	default:
		return map[string]any{"echo": req.Method}
	}
}
