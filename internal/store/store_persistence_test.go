package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestNewWithPathCorruptSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithPath(path); err == nil {
		t.Fatal("a corrupt snapshot must return an error, not load silently")
	}
}

func TestNewWithPathFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(path, []byte(`{"version":999999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithPath(path); err == nil {
		t.Fatal("a future snapshot version must be rejected")
	}
}

func TestNewWithPathMissingFileStartsEmpty(t *testing.T) {
	s, err := NewWithPath(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || s == nil {
		t.Fatalf("a missing snapshot should start empty, got err=%v", err)
	}
}

func TestSnapshotPersistRoundTrip(t *testing.T) {
	t.Setenv("OATD_AUDIT_HMAC_SECRET", "rt-secret")
	path := filepath.Join(t.TempDir(), "snap.json")
	now := time.Now()

	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddEvent(domain.Event{ID: "e1", Timestamp: now, Kind: domain.EventAgentToolCall, AssetID: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddAudit(domain.AuditEvent{ID: "a1", Timestamp: now, Action: "x", ResourceType: "y", Outcome: "ok"}); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	events, _, _, _, audits := reloaded.Counts()
	if events != 1 || audits != 1 {
		t.Fatalf("snapshot did not persist: events=%d audits=%d", events, audits)
	}
	if !reloaded.AuditChain().Valid {
		t.Fatal("the reloaded audit chain should still be valid")
	}
}

func TestNewWithPostgresUnreachableDSN(t *testing.T) {
	// Connection refused on port 1 -> the DB layer fails gracefully, never a
	// panic or an unbounded hang.
	if _, err := NewWithPostgres("postgres://user:pass@127.0.0.1:1/db?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("an unreachable DSN must return an error")
	}
}
