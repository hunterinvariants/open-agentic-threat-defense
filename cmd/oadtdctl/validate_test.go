package main

import (
	"testing"

	"github.com/open-agentic-threat-defense/oadtd/internal/domain"
)

func TestVerdictRankOrdering(t *testing.T) {
	if !(verdictRank(domain.GatewayDeny) > verdictRank(domain.GatewayRequireApproval) &&
		verdictRank(domain.GatewayRequireApproval) > verdictRank(domain.GatewayAllow)) {
		t.Fatal("verdict rank must order deny > require_approval > allow")
	}
}

func TestValidationCasesWellFormed(t *testing.T) {
	cases := validationCases("validation-agent")
	if len(cases) < 8 {
		t.Fatalf("expected a meaningful emulation library, got %d", len(cases))
	}
	sawBenign := false
	names := make(map[string]bool, len(cases))
	for _, c := range cases {
		if c.name == "" || c.technique == "" || c.tactic == "" {
			t.Fatalf("case missing name/technique/tactic: %+v", c)
		}
		if names[c.name] {
			t.Fatalf("duplicate case name %q", c.name)
		}
		names[c.name] = true
		switch c.want {
		case domain.GatewayAllow, domain.GatewayRequireApproval, domain.GatewayDeny:
		default:
			t.Fatalf("case %s has invalid want verdict %q", c.name, c.want)
		}
		if c.req.ToolName == "" {
			t.Fatalf("case %s has an empty tool name", c.name)
		}
		if c.want == domain.GatewayAllow {
			sawBenign = true
			if c.atLeast {
				t.Fatalf("benign case %s must be an exact match (atLeast=false)", c.name)
			}
		}
	}
	if !sawBenign {
		t.Fatal("the suite must include a benign baseline to catch false positives")
	}
}
