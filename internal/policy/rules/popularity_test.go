package rules_test

import (
	"testing"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
)

func int64Ptr(v int64) *int64 { return &v }

func TestMinDownloads_Allow(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "popular",
			Version:             "1.0.0",
			DownloadsLast30Days: int64Ptr(50000),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (allow), got %+v", out)
	}
}

func TestMinDownloads_Block_TooLow(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "obscure",
			Version:             "0.0.1",
			DownloadsLast30Days: int64Ptr(42),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Error("expected Block for low download count")
	}
}

func TestMinDownloads_Block_NilCount(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Name: "pkg", Version: "1.0.0"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Error("expected Block when download count is unavailable")
	}
}
