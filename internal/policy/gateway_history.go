package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

// Gateway call-history is keyed per session/run/actor and would otherwise grow
// unbounded under real traffic. Cap the number of tracked keys and evict the
// oldest in batches so memory stays bounded. Vars (not consts) so tests can
// exercise the eviction with a small cap.
var (
	maxGatewayHistoryEntries = 50000
	gatewayHistoryEvictBatch = 5000
)

type gatewayHistoryState struct {
	Calls         int
	AllowCount    int
	ApprovalCount int
	DenyCount     int
	RiskScoreMax  int
	LastSeen      time.Time
	LastTool      string
	LastVerdict   domain.GatewayVerdict
	RecentFactors []string
}

type gatewayHistorySnapshot struct {
	Key           string
	Calls         int
	AllowCount    int
	ApprovalCount int
	DenyCount     int
	RiskScoreMax  int
	LastSeen      time.Time
	LastTool      string
	LastVerdict   string
	RecentFactors []string
}

func gatewayHistoryKey(request domain.ToolCallRequest) string {
	for _, key := range []string{"session_id", "conversation_id", "run_id", "agent_id", "trace_id"} {
		if value := strings.TrimSpace(request.Metadata[key]); value != "" {
			return key + ":" + strings.ToLower(value)
		}
	}
	if value := strings.TrimSpace(request.Actor); value != "" {
		return "actor:" + strings.ToLower(value)
	}
	if value := strings.TrimSpace(request.AssetID); value != "" {
		return "asset:" + strings.ToLower(value)
	}
	return "global"
}

func (e *Engine) gatewayHistorySnapshot(request domain.ToolCallRequest) gatewayHistorySnapshot {
	key := gatewayHistoryKey(request)
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	state := e.history[key]
	if state == nil {
		return gatewayHistorySnapshot{Key: key}
	}
	return state.snapshot(key)
}

func (e *Engine) recordGatewayHistory(request domain.ToolCallRequest, verdict domain.GatewayVerdict, riskScore int, factors []string, tool string) gatewayHistorySnapshot {
	key := gatewayHistoryKey(request)
	e.historyMu.Lock()
	defer e.historyMu.Unlock()

	state := e.history[key]
	if state == nil {
		if maxGatewayHistoryEntries > 0 && len(e.history) >= maxGatewayHistoryEntries {
			e.evictOldestHistoryLocked(gatewayHistoryEvictBatch)
		}
		state = &gatewayHistoryState{}
		e.history[key] = state
	}
	state.Calls++
	state.LastSeen = time.Now().UTC()
	state.LastTool = tool
	state.LastVerdict = verdict
	if riskScore > state.RiskScoreMax {
		state.RiskScoreMax = riskScore
	}
	switch verdict {
	case domain.GatewayAllow:
		state.AllowCount++
	case domain.GatewayRequireApproval:
		state.ApprovalCount++
	case domain.GatewayDeny:
		state.DenyCount++
	}
	state.RecentFactors = appendHistoryValues(state.RecentFactors, factors, 8)
	return state.snapshot(key)
}

// evictOldestHistoryLocked removes the n entries with the oldest LastSeen. The
// caller must hold historyMu. The sort runs only when the cap is exceeded (once
// per eviction batch), so the cost is amortized across many inserts.
func (e *Engine) evictOldestHistoryLocked(n int) {
	if n <= 0 || len(e.history) == 0 {
		return
	}
	type entry struct {
		key      string
		lastSeen time.Time
	}
	entries := make([]entry, 0, len(e.history))
	for k, s := range e.history {
		entries = append(entries, entry{k, s.LastSeen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastSeen.Before(entries[j].lastSeen) })
	if n > len(entries) {
		n = len(entries)
	}
	for i := 0; i < n; i++ {
		delete(e.history, entries[i].key)
	}
}

func (s *gatewayHistoryState) snapshot(key string) gatewayHistorySnapshot {
	return gatewayHistorySnapshot{
		Key:           key,
		Calls:         s.Calls,
		AllowCount:    s.AllowCount,
		ApprovalCount: s.ApprovalCount,
		DenyCount:     s.DenyCount,
		RiskScoreMax:  s.RiskScoreMax,
		LastSeen:      s.LastSeen,
		LastTool:      s.LastTool,
		LastVerdict:   string(s.LastVerdict),
		RecentFactors: append([]string(nil), s.RecentFactors...),
	}
}

func appendHistoryValues(existing []string, incoming []string, max int) []string {
	for _, value := range incoming {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		existing = append(existing, value)
	}
	if max > 0 && len(existing) > max {
		existing = existing[len(existing)-max:]
	}
	return existing
}

func (s gatewayHistorySnapshot) contextString() string {
	parts := []string{
		fmt.Sprintf("calls=%d", s.Calls),
		fmt.Sprintf("allow=%d", s.AllowCount),
		fmt.Sprintf("approval=%d", s.ApprovalCount),
		fmt.Sprintf("deny=%d", s.DenyCount),
		fmt.Sprintf("max_risk=%d", s.RiskScoreMax),
	}
	if s.LastTool != "" {
		parts = append(parts, "last_tool="+s.LastTool)
	}
	if s.LastVerdict != "" {
		parts = append(parts, "last_verdict="+s.LastVerdict)
	}
	if !s.LastSeen.IsZero() {
		parts = append(parts, "last_seen="+s.LastSeen.Format(time.RFC3339))
	}
	return strings.Join(parts, ";")
}
