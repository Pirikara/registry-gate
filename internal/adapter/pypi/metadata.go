package pypi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
)

// JSONAPIResponse is the top-level object from GET https://pypi.org/pypi/<pkg>/json
//
// NOTE: PyPI's JSON API does NOT include provenance/attestation data. Provenance
// is exposed via a separate PEP 740 endpoint:
//
//	GET /integrity/<pkg>/<ver>/<filename>/provenance
//
// Trust signals are therefore fetched out-of-band by the adapter, not derived
// from this response.
type JSONAPIResponse struct {
	Info     PackageInfo                `json:"info"`
	Releases map[string][]ReleaseFile   `json:"releases"`
	URLs     []ReleaseFile              `json:"urls"`
}

type PackageInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	Author      string `json:"author"`
	License     string `json:"license"`
	RequiresDist []string `json:"requires_dist"`
	Yanked      bool   `json:"yanked"`
	YankedReason string `json:"yanked_reason"`
}

type ReleaseFile struct {
	Filename      string            `json:"filename"`
	URL           string            `json:"url"`
	PackageType   string            `json:"packagetype"` // "bdist_wheel" | "sdist"
	UploadTime    string            `json:"upload_time"`
	UploadTimeISO string            `json:"upload_time_iso_8601"`
	Yanked        bool              `json:"yanked"`
	Digests       map[string]string `json:"digests"`
}

// PEP740Bundle is the response from the PyPI integrity provenance endpoint.
// 200 means provenance exists; 404 means the file was uploaded without it.
type PEP740Bundle struct {
	Version            int                 `json:"version"`
	AttestationBundles []AttestationBundle `json:"attestation_bundles"`
}

type AttestationBundle struct {
	Publisher    *PEP740Publisher `json:"publisher,omitempty"`
	Attestations []json.RawMessage `json:"attestations"`
}

// PEP740Publisher describes the OIDC trusted-publishing identity that signed
// the upload. Fields mirror the PyPI integrity API.
type PEP740Publisher struct {
	Kind        string `json:"kind"`        // e.g. "GitHub"
	Repository  string `json:"repository"`  // e.g. "sigstore/sigstore-python"
	Workflow    string `json:"workflow"`    // e.g. "release.yml"
	Environment string `json:"environment,omitempty"`
}

// ToTrustSignals converts a successful PEP 740 fetch into trust facts.
// Provenance.Verified is true because PyPI returns the bundle only after
// verifying it against Sigstore's transparency log.
func (b *PEP740Bundle) ToTrustSignals() *facts.TrustSignals {
	t := &facts.TrustSignals{
		Provenance: &facts.ProvenanceSignal{Present: true, Verified: true},
	}
	if len(b.AttestationBundles) == 0 {
		return t
	}
	pub := b.AttestationBundles[0].Publisher
	if pub == nil {
		return t
	}
	t.Provenance.BuilderType = pub.Kind
	t.Provenance.SourceRepo = pub.Repository
	t.Publisher = &facts.PublisherSignal{
		ID:    pub.Repository,
		Level: facts.TrustTrustedPublisher,
	}
	return t
}

// NoProvenanceTrust is the trust fact set returned when the PEP 740 endpoint
// returns 404 — the file exists but was uploaded without trusted publishing.
func NoProvenanceTrust() *facts.TrustSignals {
	return &facts.TrustSignals{
		Provenance: &facts.ProvenanceSignal{Present: false},
		Publisher:  &facts.PublisherSignal{Level: facts.TrustUser},
	}
}

func ParseJSONAPI(data []byte) (*JSONAPIResponse, error) {
	var resp JSONAPIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse pypi json api: %w", err)
	}
	return &resp, nil
}

// ToPackageFacts converts a specific version's release files into PackageFacts.
// Trust signals are NOT populated here — the adapter fetches them from the
// PEP 740 endpoint and assigns them after this call returns.
func (r *JSONAPIResponse) ToPackageFacts(version string) (*facts.PackageFacts, error) {
	files, ok := r.Releases[version]
	if !ok || len(files) == 0 {
		return nil, fmt.Errorf("version %s not found in PyPI response for %s", version, r.Info.Name)
	}

	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemPyPI,
		Name:      r.Info.Name,
		Version:   version,
		Yanked:    r.Info.Yanked,
	}

	var earliest time.Time
	for _, f := range files {
		ts := f.UploadTimeISO
		if ts == "" {
			ts = f.UploadTime
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", ts)
		}
		if err == nil && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	if !earliest.IsZero() {
		pf.PublishedAt = earliest
		pf.AgeDays = time.Since(earliest).Hours() / 24
	}

	return pf, nil
}

// PrimaryFilename returns the filename to use when fetching provenance for a
// version. PyPI exposes provenance per-file; we pick the wheel if any, else
// the first file.
func (r *JSONAPIResponse) PrimaryFilename(version string) string {
	files := r.Releases[version]
	for _, f := range files {
		if strings.HasSuffix(f.Filename, ".whl") {
			return f.Filename
		}
	}
	if len(files) > 0 {
		return files[0].Filename
	}
	return ""
}

// SimpleIndex represents the PEP 503 simple repository index for a package.
type SimpleIndex struct {
	Name  string
	Files []SimpleFile
}

type SimpleFile struct {
	Filename string
	URL      string
	DataDist string // "wheel" | "source"
}

// RewriteFileURLs replaces file download URLs with proxy-routed equivalents.
func (si *SimpleIndex) RewriteFileURLs(proxyBaseURL string) {
	base := strings.TrimRight(proxyBaseURL, "/")
	for i := range si.Files {
		origURL := si.Files[i].URL
		if idx := strings.LastIndex(origURL, "/"); idx >= 0 {
			filename := origURL[idx+1:]
			if h := strings.Index(filename, "#"); h >= 0 {
				filename = filename[:h]
			}
			si.Files[i].URL = base + "/packages/" + si.Files[i].Filename + "#sha256=" + digestFromURL(origURL)
			_ = filename
		}
	}
}

func digestFromURL(url string) string {
	if idx := strings.Index(url, "#sha256="); idx >= 0 {
		return url[idx+8:]
	}
	return ""
}
