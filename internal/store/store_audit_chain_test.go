package store

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// TestAuditChainValidAndLinked verifies that appended audit events form a valid,
// hash-linked, anchored chain — the tamper-evidence guarantee the product makes.
func TestAuditChainValidAndLinked(t *testing.T) {
	t.Setenv("OATD_AUDIT_HMAC_SECRET", "test-audit-secret")
	s := New()
	for i := 0; i < 5; i++ {
		if err := s.AddAudit(domain.AuditEvent{
			ID: fmt.Sprintf("au-%d", i), Timestamp: time.Now(),
			Action: "act", ResourceType: "res", Outcome: "ok",
		}); err != nil {
			t.Fatal(err)
		}
	}

	snap := s.AuditChain()
	if !snap.Valid {
		t.Fatalf("audit chain should be valid with an anchor, got %+v", snap)
	}
	if snap.Total != 5 || snap.Linked != 5 {
		t.Fatalf("expected 5 linked entries, got total=%d linked=%d", snap.Total, snap.Linked)
	}
	if !snap.Anchored || snap.Anchor == "" {
		t.Fatalf("chain should be anchored, got %+v", snap)
	}

	audits := s.ListAudits()
	sort.Slice(audits, func(i, j int) bool { return audits[i].ChainIndex < audits[j].ChainIndex })
	for i, a := range audits {
		if a.Hash == "" {
			t.Fatalf("audit %s is missing its hash", a.ID)
		}
		if i > 0 && a.PrevHash != audits[i-1].Hash {
			t.Fatalf("chain broken at index %d: prev=%q want=%q", a.ChainIndex, a.PrevHash, audits[i-1].Hash)
		}
	}
}
