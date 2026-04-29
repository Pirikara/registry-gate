package rubygems

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
)

// VersionList is the response from GET /api/v1/versions/<name>.json
// (used to enumerate versions; does NOT include rubygems_mfa_required).
type VersionList []VersionInfo

type VersionInfo struct {
	Number      string `json:"number"`
	CreatedAt   string `json:"created_at"`
	AuthorNames string `json:"authors"`
	Yanked      bool   `json:"yanked"`
	Downloads   int64  `json:"downloads_count"`
}

// VersionDetail is the response from
// GET /api/v2/rubygems/<name>/versions/<version>.json
// — this endpoint exposes per-version metadata including the
// rubygems_mfa_required flag, which is the only trust signal
// rubygems.org currently surfaces via JSON API.
type VersionDetail struct {
	Name             string                 `json:"name"`
	Number           string                 `json:"number"`
	Authors          string                 `json:"authors"`
	VersionCreatedAt string                 `json:"version_created_at"`
	CreatedAt        string                 `json:"created_at"`
	SourceCodeURI    string                 `json:"source_code_uri"`
	Yanked           bool                   `json:"yanked"`
	Metadata         map[string]string      `json:"metadata"`
	Dependencies     map[string]any         `json:"dependencies,omitempty"`
}

func ParseVersionList(data []byte) (VersionList, error) {
	var vl VersionList
	if err := json.Unmarshal(data, &vl); err != nil {
		return nil, fmt.Errorf("parse version list: %w", err)
	}
	return vl, nil
}

func ParseVersionDetail(data []byte) (*VersionDetail, error) {
	var vd VersionDetail
	if err := json.Unmarshal(data, &vd); err != nil {
		return nil, fmt.Errorf("parse version detail: %w", err)
	}
	return &vd, nil
}

// ToPackageFacts converts a VersionInfo into PackageFacts without trust
// signals. Used when only the version list is available (no per-version
// detail fetched yet).
func (vi VersionInfo) ToPackageFacts(name string) *facts.PackageFacts {
	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemRubyGems,
		Name:      name,
		Version:   vi.Number,
		Yanked:    vi.Yanked,
	}
	if vi.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, vi.CreatedAt); err == nil {
			pf.PublishedAt = t
			pf.AgeDays = time.Since(t).Hours() / 24
		}
	}
	// downloads_count is lifetime total downloads for this version.
	// Semantics differ from npm's 30-day window, but useful as a popularity signal.
	d := vi.Downloads
	pf.DownloadCount = &d
	return pf
}

// ToPackageFacts on VersionDetail builds full facts including TrustSignals
// derived from the rubygems_mfa_required flag and the authors string.
func (vd *VersionDetail) ToPackageFacts() *facts.PackageFacts {
	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemRubyGems,
		Name:      vd.Name,
		Version:   vd.Number,
		Yanked:    vd.Yanked,
	}
	ts := vd.VersionCreatedAt
	if ts == "" {
		ts = vd.CreatedAt
	}
	if ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			pf.PublishedAt = t
			pf.AgeDays = time.Since(t).Hours() / 24
		}
	}
	pf.Trust = vd.extractTrust()
	return pf
}

// extractTrust builds TrustSignals from rubygems_mfa_required and authors.
// rubygems.org does not surface provenance/sigstore data via JSON API.
func (vd *VersionDetail) extractTrust() *facts.TrustSignals {
	mfa := vd.Metadata["rubygems_mfa_required"]
	var twoFA *bool
	switch mfa {
	case "true":
		v := true
		twoFA = &v
	case "false":
		v := false
		twoFA = &v
	}
	// No explicit MFA flag and no other trust evidence: skip.
	if twoFA == nil && vd.Authors == "" {
		return nil
	}
	return &facts.TrustSignals{
		Publisher: &facts.PublisherSignal{
			ID:               vd.Authors,
			Level:            facts.TrustUser,
			TwoFactorEnabled: twoFA,
		},
	}
}
