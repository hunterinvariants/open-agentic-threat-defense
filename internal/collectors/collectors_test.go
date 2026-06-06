package collectors

import (
	"strings"
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestNormalizeSuricataEVE(t *testing.T) {
	input := strings.NewReader(`{"timestamp":"2026-06-06T12:00:00Z","event_type":"alert","src_ip":"10.0.0.5","dest_ip":"203.0.113.9","dest_port":443,"proto":"TCP","alert":{"signature":"Test canary egress","signature_id":1001,"category":"Policy","severity":2}}`)

	events, err := Normalize(SourceSuricataEVE, input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != domain.EventFinding {
		t.Fatalf("expected finding, got %s", events[0].Kind)
	}
	if events[0].Destination != "203.0.113.9:443" {
		t.Fatalf("unexpected destination: %s", events[0].Destination)
	}
}

func TestNormalizeZeekConnTSV(t *testing.T) {
	input := strings.NewReader("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n1717675200.0\tC1\t10.0.0.5\t51512\t203.0.113.9\t443\ttcp\tssl\n")

	events, err := Normalize(SourceZeekConn, input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != domain.EventNetworkFlow {
		t.Fatalf("expected network flow, got %s", events[0].Kind)
	}
	if events[0].SourceIP != "10.0.0.5" || events[0].Destination != "203.0.113.9:443" {
		t.Fatalf("unexpected flow: %s -> %s", events[0].SourceIP, events[0].Destination)
	}
}

func TestNormalizeSysmonJSON(t *testing.T) {
	input := strings.NewReader(`{"EventID":1,"Computer":"win-01","EventData":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"whoami; ipconfig /all"}}`)

	events, err := Normalize(SourceSysmonJSON, input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != domain.EventProcessStart {
		t.Fatalf("expected process start, got %s", events[0].Kind)
	}
	if events[0].Hostname != "win-01" {
		t.Fatalf("unexpected host: %s", events[0].Hostname)
	}
}

func TestNormalizeAuditd(t *testing.T) {
	input := strings.NewReader(`type=EXECVE msg=audit(1717675200.0:42): argc=2 a0="curl" a1="https://example.com" node=linux-01`)

	events, err := Normalize(SourceAuditd, input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Kind != domain.EventProcessStart {
		t.Fatalf("expected process start, got %s", events[0].Kind)
	}
	if events[0].AssetID != "linux-01" {
		t.Fatalf("unexpected asset: %s", events[0].AssetID)
	}
}
