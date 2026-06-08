package auth

import "testing"

// M5: IdP/SSO-asserted roles must be filtered to the known application set so an
// injected or unmapped role string cannot grant access.
func TestNormalizeRolesFiltersUnknown(t *testing.T) {
	got := normalizeRoles([]string{"admin", "Operator", "wheel", "", "group:engineers", "viewer", "viewer"})
	if len(got) != 3 {
		t.Fatalf("expected 3 known roles after filtering, got %v", got)
	}
	want := map[string]bool{RoleAdmin: true, RoleOperator: true, RoleViewer: true}
	for _, r := range got {
		if !want[r] {
			t.Fatalf("unexpected role kept: %q", r)
		}
	}
	if len(normalizeRoles([]string{"wheel", "group:x", "superuser"})) != 0 {
		t.Fatal("entirely-unknown roles must yield no access")
	}
}
