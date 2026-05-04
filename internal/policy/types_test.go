package policy_test

import (
	"testing"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
)

func TestMatchPackagePattern(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "@scope/pkg", true},
		{"pandas*", "pandas-ext", true},
		{"pandas*", "numpy", false},
		{"@scope/*", "@scope/pkg", true},
		{"@scope/*", "@other/pkg", false},
		{"*-plugin", "auth-plugin", true},
	}

	for _, tt := range tests {
		if got := policy.MatchPackagePattern(tt.pattern, tt.name); got != tt.want {
			t.Fatalf("MatchPackagePattern(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestMatch_ExcludePackagePatternWins(t *testing.T) {
	m := policy.Match{
		Ecosystems: []facts.Ecosystem{facts.EcosystemPyPI},
		PackagePatterns: []policy.PackagePattern{{
			Ecosystem: facts.EcosystemPyPI,
			Pattern:   "pandas*",
		}},
		ExcludePackagePatterns: []policy.PackagePattern{{
			Ecosystem: facts.EcosystemPyPI,
			Pattern:   "pandas",
		}},
	}

	if m.Matches(facts.PackageFacts{Ecosystem: facts.EcosystemPyPI, Name: "pandas"}) {
		t.Fatal("expected exclude pattern to win over include pattern")
	}
	if !m.Matches(facts.PackageFacts{Ecosystem: facts.EcosystemPyPI, Name: "pandas-ext"}) {
		t.Fatal("expected included non-excluded package to match")
	}
}
