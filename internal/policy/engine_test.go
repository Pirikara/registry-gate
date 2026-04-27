package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
)

// buildEngine creates an engine and a helper that injects the given baseline
// into every Evaluate call (mimicking what an adapter does in production).
func buildEngine(entries []policy.Entry, baseline []facts.PackageFacts) *engineHarness {
	return &engineHarness{
		eng:      policy.NewEngine(entries),
		baseline: baseline,
	}
}

type engineHarness struct {
	eng      *policy.Engine
	baseline []facts.PackageFacts
}

func (h *engineHarness) Evaluate(ctx context.Context, target facts.PackageFacts, opts ...policy.EvalOption) (*policy.Result, error) {
	if len(opts) == 0 {
		opts = append(opts, policy.WithBaseline(h.baseline))
	}
	return h.eng.Evaluate(ctx, target, opts...)
}

func oldPkg(name, version string, ageDays float64) facts.PackageFacts {
	return facts.PackageFacts{
		Ecosystem:   facts.EcosystemNPM,
		Name:        name,
		Version:     version,
		PublishedAt: time.Now().AddDate(0, 0, -int(ageDays)),
		AgeDays:     ageDays,
	}
}

// 正常系: cooldown pass → allow
func TestEngine_CooldownAllow(t *testing.T) {
	eng := buildEngine([]policy.Entry{
		{Rule: rules.NewCooldown("cooldown-7d", 7)},
	}, nil)

	res, err := eng.Evaluate(context.Background(), oldPkg("lodash", "4.17.21", 30))
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionAllow {
		t.Errorf("expected Allow, got %v", res.Decision)
	}
}

// 異常系: cooldown fail → block
func TestEngine_CooldownBlock(t *testing.T) {
	eng := buildEngine([]policy.Entry{
		{Rule: rules.NewCooldown("cooldown-7d", 7)},
	}, nil)

	res, err := eng.Evaluate(context.Background(), oldPkg("new-pkg", "1.0.0", 2))
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionBlock {
		t.Errorf("expected Block, got %v", res.Decision)
	}
}

// allow が先に来れば cooldown を上書きする (declaration order = priority).
func TestEngine_AllowFirstBypassesCooldown(t *testing.T) {
	eng := buildEngine([]policy.Entry{
		{
			Match: policy.Match{Packages: []policy.PackageRef{{Ecosystem: facts.EcosystemNPM, Name: "lodash"}}},
			Rule:  rules.NewAllow("allow", []policy.PackageRef{{Ecosystem: facts.EcosystemNPM, Name: "lodash"}}),
		},
		{Rule: rules.NewCooldown("cd", 7)},
	}, nil)

	// Brand-new package but in allowlist.
	res, err := eng.Evaluate(context.Background(), oldPkg("lodash", "5.0.0", 1))
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionAllow {
		t.Errorf("expected Allow via earlier allowlist, got %v", res.Decision)
	}
}

// deny が cooldown より先で短絡 block.
func TestEngine_DenyShortCircuits(t *testing.T) {
	eng := buildEngine([]policy.Entry{
		{
			Match: policy.Match{Packages: []policy.PackageRef{{Ecosystem: facts.EcosystemNPM, Name: "evil"}}},
			Rule:  rules.NewDeny("deny", []policy.PackageRef{{Ecosystem: facts.EcosystemNPM, Name: "evil"}}),
		},
		{Rule: rules.NewCooldown("cd", 7)},
	}, nil)

	res, err := eng.Evaluate(context.Background(), oldPkg("evil", "1.0.0", 30))
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionBlock {
		t.Errorf("expected Block, got %v", res.Decision)
	}
	if res.BlockReason() == "" {
		t.Error("expected non-empty BlockReason")
	}
}

// match criteria でエコシステムが外れた場合はスキップ
func TestEngine_Match_EcosystemSkip(t *testing.T) {
	eng := buildEngine([]policy.Entry{
		{
			Match: policy.Match{Ecosystems: []facts.Ecosystem{facts.EcosystemNPM}},
			Rule:  rules.NewCooldown("cd", 7),
		},
	}, nil)

	pypiPkg := facts.PackageFacts{
		Ecosystem:   facts.EcosystemPyPI,
		Name:        "requests",
		Version:     "2.0.0",
		PublishedAt: time.Now().AddDate(0, 0, -1),
		AgeDays:     1,
	}
	res, err := eng.Evaluate(context.Background(), pypiPkg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionAllow {
		t.Errorf("expected Allow for non-matching ecosystem, got %v", res.Decision)
	}
}

// WithBaseline: per-call inline baseline drives trust_downgrade.
func TestEngine_WithBaseline(t *testing.T) {
	entries := []policy.Entry{
		{Rule: rules.NewTrustDowngrade("td",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownIgnore,
		)},
	}
	eng := policy.NewEngine(entries)

	// Target has no provenance; baseline has provenance → block.
	target := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "p", Version: "2.0.0",
		Trust: &facts.TrustSignals{Provenance: &facts.ProvenanceSignal{Present: false}},
	}
	res, err := eng.Evaluate(context.Background(), target,
		policy.WithBaseline([]facts.PackageFacts{
			{
				Ecosystem: facts.EcosystemNPM, Name: "p",
				Trust: &facts.TrustSignals{
					Provenance: &facts.ProvenanceSignal{Present: true, Verified: true},
				},
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionBlock {
		t.Errorf("baseline=present + target=absent should Block, got %v", res.Decision)
	}

	// No baseline + on_unknown=ignore → allow.
	res2, _ := eng.Evaluate(context.Background(), target, policy.WithBaseline(nil))
	if res2.Decision != policy.DecisionAllow {
		t.Errorf("empty baseline with on_unknown=ignore should Allow, got %v", res2.Decision)
	}
}

// trust_downgrade と cooldown を複数 entry として並べる
func TestEngine_TrustDowngradeAndCooldown(t *testing.T) {
	trustedPkg := facts.PackageFacts{
		Ecosystem: facts.EcosystemNPM, Name: "mypkg",
		Trust: &facts.TrustSignals{
			Provenance: &facts.ProvenanceSignal{Present: true, Verified: true},
			Publisher:  &facts.PublisherSignal{ID: "alice", Level: facts.TrustTrustedPublisher},
		},
	}
	baseline := []facts.PackageFacts{trustedPkg, trustedPkg}

	eng := buildEngine([]policy.Entry{
		{Rule: rules.NewCooldown("cd", 7)},
		{Rule: rules.NewTrustDowngrade("td",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownWarn,
		)},
	}, baseline)

	// Passes cooldown, but provenance is gone → block from trust_downgrade.
	target := facts.PackageFacts{
		Ecosystem:   facts.EcosystemNPM,
		Name:        "mypkg",
		Version:     "2.0.0",
		PublishedAt: time.Now().AddDate(0, 0, -30),
		AgeDays:     30,
		Trust: &facts.TrustSignals{
			Provenance: &facts.ProvenanceSignal{Present: false},
			Publisher:  &facts.PublisherSignal{ID: "alice", Level: facts.TrustTrustedPublisher},
		},
	}
	res, err := eng.Evaluate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionBlock {
		t.Errorf("expected Block from trust_downgrade, got %v", res.Decision)
	}
}
