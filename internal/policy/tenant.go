package policy

import (
	"sort"
	"strings"
)

// TenantPolicy is an org-scoped override of the approved-tool and approved-egress
// allowlists. A non-empty list replaces the corresponding global list for that
// tenant's gateway and detection decisions; an empty or omitted list falls back
// to the global policy for that dimension.
type TenantPolicy struct {
	TenantID       string   `json:"tenant_id"`
	ApprovedTools  []string `json:"approved_tools,omitempty"`
	ApprovedEgress []string `json:"approved_egress,omitempty"`
}

type compiledTenantPolicy struct {
	approvedTools  map[string]struct{}
	approvedEgress map[string]struct{}
	tools          []string
	egress         []string
}

func (p compiledTenantPolicy) hasTools() bool  { return len(p.approvedTools) > 0 }
func (p compiledTenantPolicy) hasEgress() bool { return len(p.approvedEgress) > 0 }

// SetTenantPolicy installs or replaces a tenant's org-scoped policy overlay and
// returns the normalized policy that was stored. An empty tenant ID is rejected.
func (e *Engine) SetTenantPolicy(policy TenantPolicy) (TenantPolicy, bool) {
	tenantID := strings.TrimSpace(policy.TenantID)
	if tenantID == "" {
		return TenantPolicy{}, false
	}
	compiled := compiledTenantPolicy{
		approvedTools:  make(map[string]struct{}),
		approvedEgress: make(map[string]struct{}),
	}
	for _, tool := range policy.ApprovedTools {
		if t := strings.ToLower(strings.TrimSpace(tool)); t != "" {
			if _, ok := compiled.approvedTools[t]; !ok {
				compiled.approvedTools[t] = struct{}{}
				compiled.tools = append(compiled.tools, t)
			}
		}
	}
	for _, host := range policy.ApprovedEgress {
		if h := normalizeHost(host); h != "" {
			if _, ok := compiled.approvedEgress[h]; !ok {
				compiled.approvedEgress[h] = struct{}{}
				compiled.egress = append(compiled.egress, h)
			}
		}
	}
	sort.Strings(compiled.tools)
	sort.Strings(compiled.egress)
	e.tenantMu.Lock()
	if e.tenantPolicies == nil {
		e.tenantPolicies = make(map[string]compiledTenantPolicy)
	}
	e.tenantPolicies[tenantID] = compiled
	e.tenantMu.Unlock()
	return tenantPolicyView(tenantID, compiled), true
}

// RemoveTenantPolicy deletes a tenant overlay, returning false if none existed.
func (e *Engine) RemoveTenantPolicy(tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return false
	}
	e.tenantMu.Lock()
	defer e.tenantMu.Unlock()
	if _, ok := e.tenantPolicies[tenantID]; !ok {
		return false
	}
	delete(e.tenantPolicies, tenantID)
	return true
}

// TenantPolicy returns a tenant's stored overlay, if any.
func (e *Engine) TenantPolicy(tenantID string) (TenantPolicy, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return TenantPolicy{}, false
	}
	e.tenantMu.RLock()
	defer e.tenantMu.RUnlock()
	compiled, ok := e.tenantPolicies[tenantID]
	if !ok {
		return TenantPolicy{}, false
	}
	return tenantPolicyView(tenantID, compiled), true
}

// ListTenantPolicies returns all tenant overlays sorted by tenant ID.
func (e *Engine) ListTenantPolicies() []TenantPolicy {
	e.tenantMu.RLock()
	defer e.tenantMu.RUnlock()
	ids := make([]string, 0, len(e.tenantPolicies))
	for id := range e.tenantPolicies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]TenantPolicy, 0, len(ids))
	for _, id := range ids {
		out = append(out, tenantPolicyView(id, e.tenantPolicies[id]))
	}
	return out
}

func tenantPolicyView(tenantID string, compiled compiledTenantPolicy) TenantPolicy {
	return TenantPolicy{
		TenantID:       tenantID,
		ApprovedTools:  append([]string(nil), compiled.tools...),
		ApprovedEgress: append([]string(nil), compiled.egress...),
	}
}

// toolApprovedForTenant consults the tenant overlay first (when it defines a
// tool allowlist) and otherwise falls back to the global approved-tool list.
func (e *Engine) toolApprovedForTenant(tenantID, tool string) bool {
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		e.tenantMu.RLock()
		compiled, ok := e.tenantPolicies[tenantID]
		e.tenantMu.RUnlock()
		if ok && compiled.hasTools() {
			_, found := compiled.approvedTools[tool]
			return found
		}
	}
	return e.isToolApproved(tool)
}

// egressApprovedForTenant consults the tenant overlay first (when it defines an
// egress allowlist) and otherwise falls back to the global approved-egress list.
func (e *Engine) egressApprovedForTenant(tenantID, destination string) bool {
	host := normalizeHost(destination)
	if host == "" {
		return false
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" {
		e.tenantMu.RLock()
		compiled, ok := e.tenantPolicies[tenantID]
		e.tenantMu.RUnlock()
		if ok && compiled.hasEgress() {
			_, found := compiled.approvedEgress[host]
			return found
		}
	}
	return e.isApprovedEgress(destination)
}
