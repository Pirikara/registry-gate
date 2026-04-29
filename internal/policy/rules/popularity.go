package rules

import (
	"fmt"

	"github.com/pirikara/registory-gate/internal/policy"
)

// MinDownloadsRule blocks packages with fewer downloads than the threshold
// over the configured window (currently only 30d is supported as a fact field).
type MinDownloadsRule struct {
	id        string
	Threshold int64
}

func NewMinDownloads(id string, threshold int64) *MinDownloadsRule {
	return &MinDownloadsRule{id: id, Threshold: threshold}
}

func (r *MinDownloadsRule) ID() string { return r.id }

func (r *MinDownloadsRule) Evaluate(ctx policy.EvalContext) (*policy.Outcome, error) {
	f := ctx.Target
	if f.DownloadCount == nil {
		// Unknown download count (e.g. private registry) — cannot enforce, allow.
		return nil, nil
	}

	if *f.DownloadCount < r.Threshold {
		return &policy.Outcome{
			Decision: policy.DecisionBlock,
			RuleID:   r.id,
			Reason:   "min_downloads",
			Detail: fmt.Sprintf(
				"%s@%s has %d downloads; minimum required is %d",
				f.Name, f.Version, *f.DownloadCount, r.Threshold,
			),
		}, nil
	}
	return nil, nil
}
