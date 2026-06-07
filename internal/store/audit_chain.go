package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

type AuditChainSnapshot struct {
	Total         int       `json:"total"`
	Linked        int       `json:"linked"`
	Head          string    `json:"head"`
	Previous      string    `json:"previous"`
	Valid         bool      `json:"valid"`
	Anchor        string    `json:"anchor,omitempty"`
	Anchored      bool      `json:"anchored,omitempty"`
	LastAuditID   string    `json:"last_audit_id,omitempty"`
	LastTimestamp time.Time `json:"last_timestamp,omitempty"`
}

func (s *Store) prepareAuditChainLocked(event domain.AuditEvent) domain.AuditEvent {
	index := len(s.audits) + 1
	event.ChainIndex = index
	event.PrevHash = s.auditChainHead
	event.Hash = auditEventHash(event, event.PrevHash)
	s.auditChainHead = event.Hash
	s.auditChainAnchor = auditChainAnchorValue(event.Hash, event.ChainIndex, true)
	s.auditChainValid = s.auditChainAnchor != ""
	return event
}

func (s *Store) rebuildAuditChainLocked() {
	head := ""
	previous := ""
	total := len(s.audits)
	linked := 0
	valid := true
	for _, audit := range s.audits {
		if strings.TrimSpace(audit.Hash) == "" {
			continue
		}
		if audit.ChainIndex == 0 {
			linked++
		} else {
			linked = audit.ChainIndex
		}
		if audit.PrevHash != previous {
			valid = false
		}
		if audit.Hash != auditEventHash(audit, audit.PrevHash) {
			valid = false
		}
		previous = audit.Hash
		head = audit.Hash
	}
	s.auditChainHead = head
	s.auditChainAnchor = auditChainAnchorValue(head, linked, valid)
	s.auditChainValid = valid && (total == 0 || s.auditChainAnchor != "")
}

func (s *Store) auditChainSnapshotLocked() AuditChainSnapshot {
	snap := AuditChainSnapshot{
		Total:    len(s.audits),
		Linked:   0,
		Head:     s.auditChainHead,
		Previous: "",
		Valid:    s.auditChainValid,
		Anchor:   s.auditChainAnchor,
		Anchored: s.auditChainAnchor != "",
	}
	for _, audit := range s.audits {
		if strings.TrimSpace(audit.Hash) == "" {
			continue
		}
		snap.Linked++
		if audit.Hash == s.auditChainHead {
			snap.LastAuditID = audit.ID
			snap.LastTimestamp = audit.Timestamp
			snap.Previous = audit.PrevHash
		}
	}
	if snap.Head == "" {
		snap.Valid = snap.Total == 0
		snap.Anchored = false
	}
	return snap
}

func (s *Store) AuditChainForTenant(tenant string) AuditChainSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditChainSnapshotForTenantLocked(tenant)
}

func (s *Store) auditChainSnapshotForTenantLocked(tenant string) AuditChainSnapshot {
	tenant = tenantOrDefault(tenant)
	filtered := make([]domain.AuditEvent, 0, len(s.audits))
	for _, audit := range s.audits {
		if sameTenant(audit.Tenant, tenant) {
			filtered = append(filtered, audit)
		}
	}
	snap := AuditChainSnapshot{
		Total:  len(filtered),
		Linked: 0,
		Head:   "",
		Valid:  true,
	}
	previous := ""
	for _, audit := range filtered {
		if strings.TrimSpace(audit.Hash) == "" {
			continue
		}
		snap.Linked++
		if audit.PrevHash != previous {
			snap.Valid = false
		}
		if audit.Hash != auditEventHash(audit, audit.PrevHash) {
			snap.Valid = false
		}
		previous = audit.Hash
		snap.Head = audit.Hash
		snap.LastAuditID = audit.ID
		snap.LastTimestamp = audit.Timestamp
	}
	if snap.Head == "" {
		snap.Valid = snap.Total == 0
	}
	snap.Anchor = auditChainAnchorValue(snap.Head, snap.Linked, snap.Valid)
	snap.Anchored = snap.Anchor != ""
	if snap.Total > 0 {
		snap.Valid = snap.Valid && snap.Anchored
	}
	return snap
}

func auditChainAnchorKey() []byte {
	secret := strings.TrimSpace(os.Getenv("OATD_AUDIT_HMAC_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("OATD_SESSION_SECRET"))
	}
	if secret == "" {
		return nil
	}
	return []byte(secret)
}

func auditChainAnchorValue(head string, chainIndex int, valid bool) string {
	key := auditChainAnchorKey()
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(head))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(fmt.Sprintf("%d", chainIndex)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(fmt.Sprintf("%t", valid)))
	return hex.EncodeToString(mac.Sum(nil))
}

func auditEventHash(event domain.AuditEvent, prevHash string) string {
	builder := strings.Builder{}
	builder.WriteString(prevHash)
	builder.WriteByte('|')
	builder.WriteString(event.ID)
	builder.WriteByte('|')
	builder.WriteString(event.Timestamp.UTC().Format(time.RFC3339Nano))
	builder.WriteByte('|')
	builder.WriteString(event.Actor)
	builder.WriteByte('|')
	builder.WriteString(strings.Join(event.Roles, ","))
	builder.WriteByte('|')
	builder.WriteString(event.Action)
	builder.WriteByte('|')
	builder.WriteString(event.ResourceType)
	builder.WriteByte('|')
	builder.WriteString(event.ResourceID)
	builder.WriteByte('|')
	builder.WriteString(event.Outcome)
	builder.WriteByte('|')
	builder.WriteString(event.SourceIP)
	builder.WriteByte('|')
	builder.WriteString(event.UserAgent)
	builder.WriteByte('|')
	builder.WriteString(canonicalMetadata(event.Metadata))
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func canonicalMetadata(metadata map[string]string) string {
	if len(metadata) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, metadata[key]))
	}
	return strings.Join(parts, ";")
}
