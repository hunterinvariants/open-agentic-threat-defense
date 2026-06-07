package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	LastAuditID   string    `json:"last_audit_id,omitempty"`
	LastTimestamp time.Time `json:"last_timestamp,omitempty"`
}

func (s *Store) prepareAuditChainLocked(event domain.AuditEvent) domain.AuditEvent {
	index := len(s.audits) + 1
	event.ChainIndex = index
	event.PrevHash = s.auditChainHead
	event.Hash = auditEventHash(event, event.PrevHash)
	s.auditChainHead = event.Hash
	s.auditChainValid = true
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
	s.auditChainValid = valid
	if head == "" && total > 0 {
		s.auditChainValid = true
	}
}

func (s *Store) auditChainSnapshotLocked() AuditChainSnapshot {
	snap := AuditChainSnapshot{
		Total:    len(s.audits),
		Linked:   0,
		Head:     s.auditChainHead,
		Previous: "",
		Valid:    s.auditChainValid,
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
		snap.Valid = true
	}
	return snap
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
