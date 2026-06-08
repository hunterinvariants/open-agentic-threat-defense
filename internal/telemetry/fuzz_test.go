package telemetry

import (
	"strings"
	"testing"
)

// FuzzReadJSONL ensures the JSONL ingest reader never panics on malformed input.
func FuzzReadJSONL(f *testing.F) {
	f.Add(`{"id":"e1","kind":"agent_tool_call","asset_id":"h1"}`)
	f.Add("")
	f.Add("\n\n")
	f.Add("not json\n{also not}\n")
	f.Add(`{"metadata":{"k":[1,2,{"x":null}]},"labels":123}`)
	f.Add(`{"timestamp":"not-a-time","kind":42}`)
	f.Add(`{"id":"\ud800"}`)
	f.Fuzz(func(t *testing.T, data string) {
		_, _ = ReadJSONL(strings.NewReader(data))
	})
}
