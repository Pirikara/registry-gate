package policy

import "github.com/pirikara/registry-gate/internal/facts"

// Decision is the outcome of policy evaluation.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionBlock
	DecisionWarn
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionBlock:
		return "block"
	case DecisionWarn:
		return "warn"
	default:
		return "unknown"
	}
}

// Outcome holds the result of evaluating a single rule.
type Outcome struct {
	Decision Decision
	RuleID   string
	Reason   string
	Detail   string
}

// Match filters which packages an entry applies to.
// Empty fields = match everything.
type Match struct {
	Ecosystems []facts.Ecosystem
	Packages   []PackageRef
}

func (m Match) Matches(f facts.PackageFacts) bool {
	if len(m.Ecosystems) > 0 {
		matched := false
		for _, e := range m.Ecosystems {
			if e == f.Ecosystem {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(m.Packages) > 0 {
		for _, p := range m.Packages {
			if p.Ecosystem == f.Ecosystem && p.Name == f.Name {
				return true
			}
		}
		return false
	}
	return true
}

type PackageRef struct {
	Ecosystem facts.Ecosystem
	Name      string
}

// Entry is one rule with its optional match scope. Engine evaluates entries
// in the order they were declared. The first allow short-circuits remaining
// evaluation; blocks accumulate; warns are record-only.
type Entry struct {
	Match Match
	Rule  Rule
}

// EvalContext carries the target facts plus the historical baseline
// used by comparative rules (e.g. trust_downgrade).
type EvalContext struct {
	Target   facts.PackageFacts
	Baseline []facts.PackageFacts
}

// Rule is implemented by every rule kind.
type Rule interface {
	// ID returns a stable identifier for the rule (used in Outcome.RuleID).
	ID() string
	// Evaluate returns a non-nil Outcome only when the rule has something to say.
	// nil means "rule did not fire / not applicable".
	Evaluate(ctx EvalContext) (*Outcome, error)
}
