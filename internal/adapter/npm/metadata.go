package npm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
)

// RegistryMetadata is the top-level structure returned by
// GET https://registry.npmjs.org/<package>
type RegistryMetadata struct {
	Name     string                     `json:"name"`
	Versions map[string]*VersionMeta    `json:"versions"`
	Time     map[string]string          `json:"time,omitempty"`
	DistTags map[string]string          `json:"dist-tags,omitempty"`
}

// VersionMeta holds per-version information.
type VersionMeta struct {
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Dist    DistInfo   `json:"dist"`
	// NPMUser is the publisher account.
	NPMUser *NPMUser   `json:"_npmUser,omitempty"`
	// Attestations/provenance (npm >=9 provenance)
	Attestations *Attestations `json:"attestations,omitempty"`
	// Deprecated: the npm registry historically stored this as a string
	// (deprecation message) but some packages use a boolean. FlexString
	// handles both; IsDeprecated() is the canonical way to check it.
	Deprecated FlexString `json:"deprecated,omitempty"`
}

// IsDeprecated reports whether this version is marked deprecated.
func (v *VersionMeta) IsDeprecated() bool { return v.Deprecated != "" }

// FlexString unmarshals a JSON string or bool into a string.
// "true" and true both become "true"; false and absent become "".
type FlexString string

func (f *FlexString) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" || string(data) == "false" {
		*f = ""
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = FlexString(s)
		return nil
	}
	// bool true → treat as deprecated with no message
	*f = "true"
	return nil
}

type DistInfo struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum,omitempty"`
	Integrity string `json:"integrity,omitempty"`
}

type NPMUser struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// Attestations mirrors the npm registry provenance metadata.
type Attestations struct {
	URL        string            `json:"url,omitempty"`
	Provenance *ProvenanceDetail `json:"provenance,omitempty"`
}

type ProvenanceDetail struct {
	PredicateType string `json:"predicateType,omitempty"`
	BuilderID     string `json:"builderId,omitempty"`
	SourceRepo    string `json:"sourceRepository,omitempty"`
}

// ParseMetadata decodes raw JSON from the npm registry.
func ParseMetadata(data []byte) (*RegistryMetadata, error) {
	var meta RegistryMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse npm metadata: %w", err)
	}
	return &meta, nil
}

// RewriteTarballURLs replaces the tarball URL in every version with one
// routed through the Registry Gate proxy so the tarball request is intercepted.
func (m *RegistryMetadata) RewriteTarballURLs(proxyBaseURL string) {
	proxyBaseURL = strings.TrimRight(proxyBaseURL, "/")
	for _, v := range m.Versions {
		orig := v.Dist.Tarball
		// Extract everything after the last slash — the filename.
		// npm tarball URLs look like: https://registry.npmjs.org/<pkg>/-/<pkg>-<ver>.tgz
		// We rewrite to: <proxyBase>/<pkg>/-/<pkg>-<ver>.tgz
		if idx := strings.Index(orig, "/-/"); idx != -1 {
			v.Dist.Tarball = proxyBaseURL + "/" + m.Name + orig[idx:]
		}
	}
}

// ToPackageFacts converts a single VersionMeta to the normalised PackageFacts
// used by the policy engine.
func (m *RegistryMetadata) ToPackageFacts(version string) (*facts.PackageFacts, error) {
	v, ok := m.Versions[version]
	if !ok {
		return nil, fmt.Errorf("version %s not found in metadata for %s", version, m.Name)
	}

	pf := &facts.PackageFacts{
		Ecosystem:    facts.EcosystemNPM,
		Name:         m.Name,
		Version:      version,
		IsDeprecated: v.IsDeprecated(),
	}

	// Publish time from the top-level "time" map.
	if ts, ok := m.Time[version]; ok {
		t, err := time.Parse(time.RFC3339, ts)
		if err == nil {
			pf.PublishedAt = t
			pf.AgeDays = time.Since(t).Hours() / 24
		}
	}

	pf.Trust = extractTrust(v)
	return pf, nil
}

// BaselineFromMetadata returns recent stable versions of the package
// (excluding the target version) suitable for trust_downgrade comparison.
//
// Filters applied:
//   - exclude target version
//   - exclude versions without a parseable publishedAt
//   - exclude deprecated versions
//   - exclude versions older than windowDays
//
// Result is sorted by publishedAt descending (newest first), capped at limit.
func (m *RegistryMetadata) BaselineFromMetadata(targetVersion string, windowDays, limit int) []facts.PackageFacts {
	now := time.Now()
	cutoff := now.AddDate(0, 0, -windowDays)

	var out []facts.PackageFacts
	for v := range m.Versions {
		if v == targetVersion {
			continue
		}
		pf, err := m.ToPackageFacts(v)
		if err != nil {
			continue
		}
		if pf.PublishedAt.IsZero() || pf.PublishedAt.Before(cutoff) {
			continue
		}
		if pf.IsDeprecated {
			continue
		}
		out = append(out, *pf)
	}

	// Sort newest first.
	sort.Slice(out, func(i, j int) bool {
		return out[i].PublishedAt.After(out[j].PublishedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// extractTrust builds a TrustSignals from the npm VersionMeta.
func extractTrust(v *VersionMeta) *facts.TrustSignals {
	t := &facts.TrustSignals{}

	if v.NPMUser != nil {
		level := facts.TrustUser
		pub := &facts.PublisherSignal{
			ID:    v.NPMUser.Name,
			Level: level,
		}

		// If attestations are present, the package was published via a
		// trusted CI pipeline (GitHub Actions OIDC / npm provenance).
		if v.Attestations != nil && v.Attestations.Provenance != nil {
			pub.Level = facts.TrustTrustedPublisher
		}
		t.Publisher = pub
	}

	if v.Attestations != nil {
		prov := &facts.ProvenanceSignal{Present: true}
		if p := v.Attestations.Provenance; p != nil {
			prov.BuilderType = p.BuilderID
			prov.SourceRepo = p.SourceRepo
			// Consider provenance verified when a builder ID is present.
			// In production this should validate the sigstore bundle.
			prov.Verified = p.BuilderID != ""
		}
		t.Provenance = prov
	}

	return t
}
