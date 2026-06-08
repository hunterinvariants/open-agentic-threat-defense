package store

import (
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// H4: two tenants ingesting the same asset ID (commonly a hostname) must get
// separate, isolated asset records rather than overwriting each other.
func TestAssetsAreTenantScoped(t *testing.T) {
	s := New()
	now := time.Now().UTC()
	if err := s.AddEvent(domain.Event{
		ID: "evt-a", Tenant: "tenant-a", Kind: domain.EventAgentToolCall,
		AssetID: "web-01", Hostname: "web-01", SourceIP: "10.0.0.1", Timestamp: now,
	}); err != nil {
		t.Fatalf("add event a: %v", err)
	}
	if err := s.AddEvent(domain.Event{
		ID: "evt-b", Tenant: "tenant-b", Kind: domain.EventAgentToolCall,
		AssetID: "web-01", Hostname: "web-01", SourceIP: "10.9.9.9", Timestamp: now,
	}); err != nil {
		t.Fatalf("add event b: %v", err)
	}

	if total := len(s.ListAssets()); total != 2 {
		t.Fatalf("expected 2 tenant-scoped assets for the same asset id, got %d", total)
	}

	a := s.ListAssetsForTenant("tenant-a")
	b := s.ListAssetsForTenant("tenant-b")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("each tenant must see exactly its own asset, got a=%d b=%d", len(a), len(b))
	}
	if !contains(a[0].IPs, "10.0.0.1") || contains(a[0].IPs, "10.9.9.9") {
		t.Fatalf("tenant-a asset must not contain tenant-b's IP, got %+v", a[0].IPs)
	}
	if a[0].Tenant != "tenant-a" || b[0].Tenant != "tenant-b" {
		t.Fatalf("asset tenant not populated: a=%q b=%q", a[0].Tenant, b[0].Tenant)
	}
}
