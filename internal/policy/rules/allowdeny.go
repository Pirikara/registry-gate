package rules

import (
	"fmt"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
)

type packageKey struct {
	ecosystem facts.Ecosystem
	name      string
}

// AllowRule immediately allows matched packages, bypassing further rules.
type AllowRule struct {
	id       string
	packages map[packageKey]struct{}
}

func NewAllow(id string, refs []policy.PackageRef) *AllowRule {
	m := make(map[packageKey]struct{}, len(refs))
	for _, r := range refs {
		m[packageKey{r.Ecosystem, r.Name}] = struct{}{}
	}
	return &AllowRule{id: id, packages: m}
}

func (r *AllowRule) ID() string { return r.id }

func (r *AllowRule) Evaluate(ctx policy.EvalContext) (*policy.Outcome, error) {
	f := ctx.Target
	if _, ok := r.packages[packageKey{f.Ecosystem, f.Name}]; ok {
		return &policy.Outcome{
			Decision: policy.DecisionAllow,
			RuleID:   r.id,
			Reason:   "allowlist",
			Detail:   fmt.Sprintf("%s@%s is on the allow list", f.Name, f.Version),
		}, nil
	}
	return nil, nil
}

// DenyRule immediately blocks matched packages.
type DenyRule struct {
	id       string
	packages map[packageKey]struct{}
}

func NewDeny(id string, refs []policy.PackageRef) *DenyRule {
	m := make(map[packageKey]struct{}, len(refs))
	for _, r := range refs {
		m[packageKey{r.Ecosystem, r.Name}] = struct{}{}
	}
	return &DenyRule{id: id, packages: m}
}

func (r *DenyRule) ID() string { return r.id }

func (r *DenyRule) Evaluate(ctx policy.EvalContext) (*policy.Outcome, error) {
	f := ctx.Target
	if _, ok := r.packages[packageKey{f.Ecosystem, f.Name}]; ok {
		return &policy.Outcome{
			Decision: policy.DecisionBlock,
			RuleID:   r.id,
			Reason:   "denylist",
			Detail:   fmt.Sprintf("%s@%s is on the deny list", f.Name, f.Version),
		}, nil
	}
	return nil, nil
}
