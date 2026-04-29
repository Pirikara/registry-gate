package rules_test

import (
	"testing"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestAllowRule_Match(t *testing.T) {
	r := rules.NewAllow("test-allow", []policy.PackageRef{
		{Ecosystem: facts.EcosystemNPM, Name: "lodash"},
	})
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionAllow {
		t.Errorf("expected Allow, got %v", out)
	}
}

func TestAllowRule_NoMatch(t *testing.T) {
	r := rules.NewAllow("test-allow", []policy.PackageRef{
		{Ecosystem: facts.EcosystemNPM, Name: "lodash"},
	})
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "express", Version: "4.0.0"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (no match), got %+v", out)
	}
}

func TestDenyRule_Match(t *testing.T) {
	r := rules.NewDeny("test-deny", []policy.PackageRef{
		{Ecosystem: facts.EcosystemNPM, Name: "evil-pkg"},
	})
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "evil-pkg", Version: "1.0.0"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Errorf("expected Block, got %v", out)
	}
}

func TestDenyRule_EcosystemIsolation(t *testing.T) {
	r := rules.NewDeny("test-deny", []policy.PackageRef{
		{Ecosystem: facts.EcosystemNPM, Name: "evil-pkg"},
	})
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Ecosystem: facts.EcosystemPyPI, Name: "evil-pkg", Version: "1.0.0"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Error("deny rule for npm should not fire for pypi package with same name")
	}
}
