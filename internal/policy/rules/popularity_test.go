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
			DownloadCount: int64Ptr(50000),
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
			DownloadCount: int64Ptr(42),
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

func TestMinDownloads_Allow_NilCount(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{Name: "pkg", Version: "1.0.0"},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (allow) when download count is unavailable, got %+v", out)
	}
}

// 境界値: 閾値ちょうど → allow (minimum required なので >= は通過)
func TestMinDownloads_Allow_ExactlyAtThreshold(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "pkg",
			Version:             "1.0.0",
			DownloadCount: int64Ptr(1000),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (allow) at exactly threshold, got %+v", out)
	}
}

// 境界値: 閾値の1つ下 → block
func TestMinDownloads_Block_OneBelowThreshold(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1000)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "pkg",
			Version:             "1.0.0",
			DownloadCount: int64Ptr(999),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Errorf("expected Block one below threshold, got %v", out)
	}
}

// 境界値: ダウンロード数がゼロ → block
func TestMinDownloads_Block_ZeroDownloads(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 1)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "pkg",
			Version:             "0.1.0",
			DownloadCount: int64Ptr(0),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Errorf("expected Block for zero downloads, got %v", out)
	}
}

// 境界値: 閾値が 0 → 全てのパッケージを通過させる
func TestMinDownloads_Allow_ZeroThreshold(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 0)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "pkg",
			Version:             "1.0.0",
			DownloadCount: int64Ptr(0),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (allow) when threshold is 0, got %+v", out)
	}
}

// Detail フィールドにパッケージ名・バージョン・ダウンロード数・閾値が含まれるか
func TestMinDownloads_Detail_ContainsContext(t *testing.T) {
	r := rules.NewMinDownloads("test-pop", 500)
	ctx := policy.EvalContext{
		Target: facts.PackageFacts{
			Name:                "tiny-lib",
			Version:             "0.0.1",
			DownloadCount: int64Ptr(10),
		},
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected block outcome")
	}
	for _, want := range []string{"tiny-lib", "0.0.1", "10", "500"} {
		if !containsStr(out.Detail, want) {
			t.Errorf("Detail %q should contain %q", out.Detail, want)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(sub) <= len(s) && (s == sub || func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
