package rules_test

import (
	"testing"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
)

func boolPtr(v bool) *bool { return &v }

func makePublisher(id string, level facts.TrustLevel, twoFA *bool) *facts.PublisherSignal {
	return &facts.PublisherSignal{ID: id, Level: level, TwoFactorEnabled: twoFA}
}

func makeProvenanceFact(present, verified bool, repo string) facts.PackageFacts {
	return facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM,
		Name:      "pkg",
		Trust: &facts.TrustSignals{
			Provenance: &facts.ProvenanceSignal{Present: present, Verified: verified, SourceRepo: repo},
			Publisher:  makePublisher("author", facts.TrustTrustedPublisher, boolPtr(true)),
		},
	}
}

var defaultWatch = []rules.TrustDowngradeWatch{
	rules.WatchProvenancePresent,
	rules.WatchProvenanceVerified,
	rules.WatchPublisherType,
	rules.WatchPublisherID,
	rules.WatchPublisherTwoFactor,
}

// 正常系: baseline と同等の信頼シグナル → allow
func TestTrustDowngrade_NoChange_Allow(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		makeProvenanceFact(true, true, "github.com/lodash/lodash"),
		makeProvenanceFact(true, true, "github.com/lodash/lodash"),
	}
	target := makeProvenanceFact(true, true, "github.com/lodash/lodash")
	target.Version = "4.17.22"

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil (allow), got %+v", out)
	}
}

// 異常系: provenance が消えた → block
func TestTrustDowngrade_ProvenanceLost_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		makeProvenanceFact(true, true, "github.com/lodash/lodash"),
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM,
		Name:      "pkg",
		Version:   "4.17.22",
		Trust: &facts.TrustSignals{
			Publisher: makePublisher("author", facts.TrustTrustedPublisher, boolPtr(true)),
			// Provenance is nil — signal lost
		},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Fatalf("expected Block when provenance disappears, got %v", out)
	}
	if !contains(out.Detail, "provenance.present") {
		t.Errorf("detail should mention provenance.present, got: %s", out.Detail)
	}
}

// 異常系: publisher.type が trusted_publisher → user に降格 → block
func TestTrustDowngrade_PublisherTypeDegraded_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{
				Publisher:  makePublisher("author", facts.TrustTrustedPublisher, boolPtr(true)),
				Provenance: &facts.ProvenanceSignal{Present: true, Verified: true},
			},
		},
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "pkg", Version: "2.0.0",
		Trust: &facts.TrustSignals{
			Publisher:  makePublisher("author", facts.TrustUser, boolPtr(true)),
			Provenance: &facts.ProvenanceSignal{Present: true, Verified: true},
		},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Fatalf("expected Block on publisher type demotion, got %v", out)
	}
	if !contains(out.Detail, "publisher.type") {
		t.Errorf("detail should mention publisher.type, got: %s", out.Detail)
	}
}

// 異常系: publisher.id が変わった（乗っ取りの疑い） → block
func TestTrustDowngrade_PublisherIDChanged_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{
				Publisher: makePublisher("alice", facts.TrustUser, boolPtr(true)),
			},
		},
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{
				Publisher: makePublisher("alice", facts.TrustUser, boolPtr(true)),
			},
		},
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "pkg", Version: "1.1.0",
		Trust: &facts.TrustSignals{
			Publisher: makePublisher("attacker", facts.TrustUser, boolPtr(false)),
		},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Fatalf("expected Block on publisher ID change, got %v", out)
	}
	if !contains(out.Detail, "publisher.id") {
		t.Errorf("detail should mention publisher.id, got: %s", out.Detail)
	}
}

// 異常系: 2FA が外れた → block
func TestTrustDowngrade_TwoFactorLost_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{Publisher: makePublisher("alice", facts.TrustUser, boolPtr(true))},
		},
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "pkg", Version: "1.0.1",
		Trust: &facts.TrustSignals{Publisher: makePublisher("alice", facts.TrustUser, boolPtr(false))},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Fatalf("expected Block when 2FA lost, got %v", out)
	}
}

// エッジケース: baseline が空 (初回リリース), on_unknown=warn → warn
func TestTrustDowngrade_NoBaseline_Warn(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownWarn)
	ctx := policy.EvalContext{
		Target:   facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "brand-new", Version: "0.1.0"},
		Baseline: nil,
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionWarn {
		t.Errorf("expected Warn for empty baseline with on_unknown=warn, got %v", out)
	}
}

// エッジケース: baseline が空, on_unknown=block → block
func TestTrustDowngrade_NoBaseline_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownBlock)
	ctx := policy.EvalContext{
		Target:   facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "brand-new", Version: "0.1.0"},
		Baseline: nil,
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Errorf("expected Block for empty baseline with on_unknown=block, got %v", out)
	}
}

// エッジケース: baseline が空, on_unknown=ignore → nil
func TestTrustDowngrade_NoBaseline_Ignore(t *testing.T) {
	r := rules.NewTrustDowngrade("td", defaultWatch, rules.OnUnknownIgnore)
	ctx := policy.EvalContext{
		Target:   facts.PackageFacts{Ecosystem: facts.EcosystemNPM, Name: "brand-new", Version: "0.1.0"},
		Baseline: nil,
	}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil for empty baseline with on_unknown=ignore, got %v", out)
	}
}

// エッジケース: baseline の publishers が分かれている場合は publisher.id チェックをスキップ
func TestTrustDowngrade_InconsistentBaselinePublisher_NoBlock(t *testing.T) {
	r := rules.NewTrustDowngrade("td", []rules.TrustDowngradeWatch{rules.WatchPublisherID}, rules.OnUnknownIgnore)

	baseline := []facts.PackageFacts{
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{Publisher: makePublisher("alice", facts.TrustUser, nil)},
		},
		{
			Ecosystem: facts.EcosystemNPM, Name: "pkg",
			Trust: &facts.TrustSignals{Publisher: makePublisher("bob", facts.TrustUser, nil)},
		},
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "pkg", Version: "2.0.0",
		Trust: &facts.TrustSignals{Publisher: makePublisher("charlie", facts.TrustUser, nil)},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("should not block when baseline publishers are inconsistent (can't determine baseline ID), got %v", out)
	}
}

// 多数決: baseline 3件のうち2件が provenance あり → baseline=true → 新バージョンで消えたらblock
func TestTrustDowngrade_MajorityBaseline_Block(t *testing.T) {
	r := rules.NewTrustDowngrade("td", []rules.TrustDowngradeWatch{rules.WatchProvenancePresent}, rules.OnUnknownWarn)

	baseline := []facts.PackageFacts{
		makeProvenanceFact(true, true, "repo"),
		makeProvenanceFact(true, true, "repo"),
		makeProvenanceFact(false, false, "repo"), // 1 件は false
	}
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "pkg", Version: "5.0.0",
		Trust: &facts.TrustSignals{Provenance: &facts.ProvenanceSignal{Present: false}},
	}

	ctx := policy.EvalContext{Target: target, Baseline: baseline}
	out, err := r.Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || out.Decision != policy.DecisionBlock {
		t.Errorf("expected Block (majority baseline=true, target=false), got %v", out)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
