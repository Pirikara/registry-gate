package policy

import (
	"context"
	"fmt"

	"github.com/pirikara/registory-gate/internal/facts"
)

// Result is the aggregate outcome of evaluating all entries against a package.
type Result struct {
	Decision Decision
	Outcomes []*Outcome
}

func (res *Result) BlockReason() string {
	for _, o := range res.Outcomes {
		if o.Decision == DecisionBlock {
			return fmt.Sprintf("[%s] %s: %s", o.RuleID, o.Reason, o.Detail)
		}
	}
	return ""
}

// Engine evaluates a flat, ordered list of entries against PackageFacts.
//
// Comparative rules (e.g. trust_downgrade) require a baseline of historical
// versions. The engine does not maintain its own baseline cache — adapters
// supply it inline via WithBaseline, typically by extracting it from the same
// upstream metadata response that produced the target facts.
type Engine struct {
	entries []Entry
}

// NewEngine builds an engine that evaluates entries in declaration order.
func NewEngine(entries []Entry) *Engine {
	return &Engine{entries: entries}
}

// EvalOption customises a single Evaluate call.
type EvalOption func(*evalOpts)

type evalOpts struct {
	baseline []facts.PackageFacts
}

// WithBaseline supplies the baseline (recent stable versions of the same
// package) used by comparative rules like trust_downgrade. If omitted, the
// baseline is empty and rules fall through to their on_unknown handler.
func WithBaseline(baseline []facts.PackageFacts) EvalOption {
	return func(o *evalOpts) { o.baseline = baseline }
}

// Evaluate runs all matching entries against the target package facts.
// Entries are processed in declaration order:
//   - the first allow short-circuits remaining evaluation
//   - blocks accumulate (final decision is block if any rule blocked)
//   - warns are recorded but do not change a decision that is already block
func (e *Engine) Evaluate(ctx context.Context, target facts.PackageFacts, opts ...EvalOption) (*Result, error) {
	_ = ctx
	o := &evalOpts{}
	for _, opt := range opts {
		opt(o)
	}

	res := &Result{Decision: DecisionAllow}

	for _, ent := range e.entries {
		if !ent.Match.Matches(target) {
			continue
		}
		outcome, err := ent.Rule.Evaluate(EvalContext{Target: target, Baseline: o.baseline})
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", ent.Rule.ID(), err)
		}
		if outcome == nil {
			continue
		}

		res.Outcomes = append(res.Outcomes, outcome)

		switch outcome.Decision {
		case DecisionAllow:
			res.Decision = DecisionAllow
			return res, nil
		case DecisionBlock:
			res.Decision = DecisionBlock
		case DecisionWarn:
			if res.Decision == DecisionAllow {
				res.Decision = DecisionWarn
			}
		}
	}

	return res, nil
}
