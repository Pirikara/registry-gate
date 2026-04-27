package rules

import (
	"fmt"
	"strings"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/policy"
)

// TrustDowngradeWatch enumerates the signals that can be watched.
type TrustDowngradeWatch string

const (
	WatchProvenancePresent     TrustDowngradeWatch = "provenance.present"
	WatchProvenanceVerified    TrustDowngradeWatch = "provenance.verified"
	WatchPublisherType         TrustDowngradeWatch = "publisher.type"
	WatchPublisherID           TrustDowngradeWatch = "publisher.id"
	WatchPublisherTwoFactor    TrustDowngradeWatch = "publisher.two_factor"
	WatchSignaturePresent      TrustDowngradeWatch = "signature.present"
	WatchSignatureVerified     TrustDowngradeWatch = "signature.verified"
)

// OnUnknown controls what happens when a signal value cannot be compared
// (e.g. baseline is empty or the signal is unavailable).
type OnUnknown string

const (
	OnUnknownBlock  OnUnknown = "block"
	OnUnknownWarn   OnUnknown = "warn"
	OnUnknownIgnore OnUnknown = "ignore"
)

// TrustDowngradeRule blocks a package version when its trust signals have
// regressed compared to the baseline of recent stable versions.
type TrustDowngradeRule struct {
	id        string
	Watch     []TrustDowngradeWatch
	OnUnknown OnUnknown
}

func NewTrustDowngrade(id string, watch []TrustDowngradeWatch, onUnknown OnUnknown) *TrustDowngradeRule {
	if len(watch) == 0 {
		watch = []TrustDowngradeWatch{
			WatchProvenancePresent,
			WatchProvenanceVerified,
			WatchPublisherType,
			WatchPublisherID,
			WatchPublisherTwoFactor,
		}
	}
	return &TrustDowngradeRule{id: id, Watch: watch, OnUnknown: onUnknown}
}

func (r *TrustDowngradeRule) ID() string { return r.id }

// NeedsBaseline implements the marker interface checked by the policy engine.
func (r *TrustDowngradeRule) NeedsBaseline() bool { return true }

func (r *TrustDowngradeRule) Evaluate(ctx policy.EvalContext) (*policy.Outcome, error) {
	if len(ctx.Baseline) == 0 {
		return r.handleUnknown(ctx.Target, "no baseline versions available for comparison"), nil
	}

	baseline := aggregateBaseline(ctx.Baseline)
	var violations []string

	for _, w := range r.Watch {
		violation := r.checkSignal(w, baseline, ctx.Target)
		if violation != "" {
			violations = append(violations, violation)
		}
	}

	if len(violations) == 0 {
		return nil, nil
	}

	return &policy.Outcome{
		Decision: policy.DecisionBlock,
		RuleID:   r.id,
		Reason:   "trust_downgrade",
		Detail:   strings.Join(violations, "; "),
	}, nil
}

// aggregatedBaseline holds the "majority" trust state derived from baseline versions.
type aggregatedBaseline struct {
	ProvenancePresent  *bool
	ProvenanceVerified *bool
	PublisherType      *facts.TrustLevel
	PublisherID        *string
	TwoFactor          *bool
	SignaturePresent    *bool
	SignatureVerified   *bool
}

func aggregateBaseline(versions []facts.PackageFacts) aggregatedBaseline {
	var (
		provPresentTrue, provPresentFalse     int
		provVerifiedTrue, provVerifiedFalse   int
		sigPresentTrue, sigPresentFalse       int
		sigVerifiedTrue, sigVerifiedFalse     int
		twoFactorTrue, twoFactorFalse         int
		publisherIDs                          []string
		trustLevels                           []facts.TrustLevel
	)

	for _, v := range versions {
		if v.Trust == nil {
			continue
		}
		if p := v.Trust.Provenance; p != nil {
			if p.Present {
				provPresentTrue++
			} else {
				provPresentFalse++
			}
			if p.Verified {
				provVerifiedTrue++
			} else {
				provVerifiedFalse++
			}
		}
		if s := v.Trust.Signature; s != nil {
			if s.Present {
				sigPresentTrue++
			} else {
				sigPresentFalse++
			}
			if s.Verified {
				sigVerifiedTrue++
			} else {
				sigVerifiedFalse++
			}
		}
		if pub := v.Trust.Publisher; pub != nil {
			publisherIDs = append(publisherIDs, pub.ID)
			trustLevels = append(trustLevels, pub.Level)
			if pub.TwoFactorEnabled != nil {
				if *pub.TwoFactorEnabled {
					twoFactorTrue++
				} else {
					twoFactorFalse++
				}
			}
		}
	}

	b := aggregatedBaseline{}

	if provPresentTrue+provPresentFalse > 0 {
		v := provPresentTrue > provPresentFalse
		b.ProvenancePresent = &v
	}
	if provVerifiedTrue+provVerifiedFalse > 0 {
		v := provVerifiedTrue > provVerifiedFalse
		b.ProvenanceVerified = &v
	}
	if sigPresentTrue+sigPresentFalse > 0 {
		v := sigPresentTrue > sigPresentFalse
		b.SignaturePresent = &v
	}
	if sigVerifiedTrue+sigVerifiedFalse > 0 {
		v := sigVerifiedTrue > sigVerifiedFalse
		b.SignatureVerified = &v
	}
	if twoFactorTrue+twoFactorFalse > 0 {
		v := twoFactorTrue > twoFactorFalse
		b.TwoFactor = &v
	}

	// Publisher ID: if all baseline versions share the same ID, record it.
	if len(publisherIDs) > 0 {
		allSame := true
		for _, id := range publisherIDs[1:] {
			if id != publisherIDs[0] {
				allSame = false
				break
			}
		}
		if allSame {
			b.PublisherID = &publisherIDs[0]
		}
	}

	// Trust level: use the majority maximum.
	if len(trustLevels) > 0 {
		counts := map[facts.TrustLevel]int{}
		for _, tl := range trustLevels {
			counts[tl]++
		}
		var maxLevel facts.TrustLevel
		var maxCount int
		for tl, c := range counts {
			if c > maxCount || (c == maxCount && tl > maxLevel) {
				maxLevel = tl
				maxCount = c
			}
		}
		b.PublisherType = &maxLevel
	}

	return b
}

func (r *TrustDowngradeRule) checkSignal(
	w TrustDowngradeWatch,
	base aggregatedBaseline,
	target facts.PackageFacts,
) string {
	switch w {
	case WatchProvenancePresent:
		if base.ProvenancePresent == nil {
			return r.unknownMsg(string(w))
		}
		targetVal := target.Trust != nil && target.Trust.Provenance != nil && target.Trust.Provenance.Present
		if *base.ProvenancePresent && !targetVal {
			return fmt.Sprintf("provenance.present: true → false")
		}

	case WatchProvenanceVerified:
		if base.ProvenanceVerified == nil {
			return r.unknownMsg(string(w))
		}
		targetVal := target.Trust != nil && target.Trust.Provenance != nil && target.Trust.Provenance.Verified
		if *base.ProvenanceVerified && !targetVal {
			return "provenance.verified: true → false"
		}

	case WatchPublisherType:
		if base.PublisherType == nil {
			return r.unknownMsg(string(w))
		}
		if target.Trust == nil || target.Trust.Publisher == nil {
			if *base.PublisherType > facts.TrustUnknown {
				return fmt.Sprintf("publisher.type: %s → unknown", base.PublisherType.String())
			}
			return ""
		}
		if target.Trust.Publisher.Level < *base.PublisherType {
			return fmt.Sprintf(
				"publisher.type: %s → %s",
				base.PublisherType.String(),
				target.Trust.Publisher.Level.String(),
			)
		}

	case WatchPublisherID:
		if base.PublisherID == nil {
			// Baseline publishers were not consistent; skip.
			return ""
		}
		if target.Trust == nil || target.Trust.Publisher == nil {
			return fmt.Sprintf("publisher.id: %q → unknown", *base.PublisherID)
		}
		if target.Trust.Publisher.ID != *base.PublisherID {
			return fmt.Sprintf(
				"publisher.id: %q → %q",
				*base.PublisherID,
				target.Trust.Publisher.ID,
			)
		}

	case WatchPublisherTwoFactor:
		if base.TwoFactor == nil {
			return r.unknownMsg(string(w))
		}
		if target.Trust == nil || target.Trust.Publisher == nil || target.Trust.Publisher.TwoFactorEnabled == nil {
			if *base.TwoFactor {
				return "publisher.two_factor: true → unknown"
			}
			return ""
		}
		if *base.TwoFactor && !*target.Trust.Publisher.TwoFactorEnabled {
			return "publisher.two_factor: true → false"
		}

	case WatchSignaturePresent:
		if base.SignaturePresent == nil {
			return r.unknownMsg(string(w))
		}
		targetVal := target.Trust != nil && target.Trust.Signature != nil && target.Trust.Signature.Present
		if *base.SignaturePresent && !targetVal {
			return "signature.present: true → false"
		}

	case WatchSignatureVerified:
		if base.SignatureVerified == nil {
			return r.unknownMsg(string(w))
		}
		targetVal := target.Trust != nil && target.Trust.Signature != nil && target.Trust.Signature.Verified
		if *base.SignatureVerified && !targetVal {
			return "signature.verified: true → false"
		}
	}

	return ""
}

func (r *TrustDowngradeRule) unknownMsg(signal string) string {
	if r.OnUnknown == OnUnknownBlock {
		return fmt.Sprintf("%s: baseline unknown (on_unknown=block)", signal)
	}
	// warn / ignore — don't add to violations for blocking purposes
	return ""
}

func (r *TrustDowngradeRule) handleUnknown(f facts.PackageFacts, reason string) *policy.Outcome {
	switch r.OnUnknown {
	case OnUnknownBlock:
		return &policy.Outcome{
			Decision: policy.DecisionBlock,
			RuleID:   r.id,
			Reason:   "trust_downgrade",
			Detail:   fmt.Sprintf("%s@%s: %s", f.Name, f.Version, reason),
		}
	case OnUnknownWarn:
		return &policy.Outcome{
			Decision: policy.DecisionWarn,
			RuleID:   r.id,
			Reason:   "trust_downgrade",
			Detail:   fmt.Sprintf("%s@%s: %s", f.Name, f.Version, reason),
		}
	default:
		return nil
	}
}
