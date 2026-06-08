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
	if len(cases) < 5 {
		t.Fatalf("expected a meaningful emulation library, got %d", len(cases))
	}
	sawBenign := false
	for _, c := range cases {
		if c.name == "" || c.technique == "" {
			t.Fatalf("case missing name/technique: %+v", c)
		}
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
