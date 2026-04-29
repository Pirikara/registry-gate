package rules_test

import (
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestCooldown_Allow(t *testing.T) {
	r := rules.NewCooldown("test-cooldown", 7)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:        "lodash",
			Version:     "4.17.21",
			PublishedAt: time.Now().AddDate(0, 0, -10),
			AgeDays:     10,
		},
	}
	outcome, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != nil {
		t.Errorf("expected nil outcome (allow), got %+v", outcome)
	}
}

func TestCooldown_Block_TooNew(t *testing.T) {
	r := rules.NewCooldown("test-cooldown", 7)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:        "new-pkg",
			Version:     "1.0.0",
			PublishedAt: time.Now().AddDate(0, 0, -3),
			AgeDays:     3,
		},
	}
	outcome, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == nil {
		t.Fatal("expected a block outcome, got nil")
	}
	if outcome.Decision != policy.DecisionBlock {
		t.Errorf("expected Block, got %v", outcome.Decision)
	}
}

func TestCooldown_Block_JustUnder(t *testing.T) {
	r := rules.NewCooldown("test-cooldown", 7)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:        "pkg",
			Version:     "1.0.0",
			PublishedAt: time.Now().AddDate(0, 0, -6),
			AgeDays:     6.9,
		},
	}
	outcome, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == nil || outcome.Decision != policy.DecisionBlock {
		t.Error("expected Block for age 6.9 with min 7 days")
	}
}

func TestCooldown_Block_UnknownPublishedAt(t *testing.T) {
	r := rules.NewCooldown("test-cooldown", 7)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Name: "pkg", Version: "1.0.0"},
	}
	outcome, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if outcome == nil || outcome.Decision != policy.DecisionBlock {
		t.Error("expected Block when published_at is unknown")
	}
}
