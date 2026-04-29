package rules

import (
	"fmt"
	"math"

	"github.com/pirikara/registry-gate/internal/policy"
)

// CooldownRule blocks packages that were published less than MinAgeDays ago.
type CooldownRule struct {
	id         string
	MinAgeDays float64
}

func NewCooldown(id string, minAgeDays float64) *CooldownRule {
	return &CooldownRule{id: id, MinAgeDays: minAgeDays}
}

func (r *CooldownRule) ID() string { return r.id }

func (r *CooldownRule) Evaluate(ctx policy.EvalContext) (*policy.Outcome, error) {
	f := ctx.Target
	if f.PublishedAt.IsZero() {
		return &policy.Outcome{
			Decision: policy.DecisionBlock,
			RuleID:   r.id,
			Reason:   "cooldown",
			Detail:   "published_at is unknown; cannot verify cooldown requirement",
		}, nil
	}

	ageDays := math.Round(f.AgeDays*100) / 100
	if ageDays < r.MinAgeDays {
		return &policy.Outcome{
			Decision: policy.DecisionBlock,
			RuleID:   r.id,
			Reason:   "cooldown",
			Detail: fmt.Sprintf(
				"%s@%s was published %.1f day(s) ago; minimum required age is %.0f day(s)",
				f.Name, f.Version, ageDays, r.MinAgeDays,
			),
		}, nil
	}
	return nil, nil
}
