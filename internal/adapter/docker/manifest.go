package docker

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pirikara/registory-gate/internal/facts"
)

// Manifest media types we handle.
const (
	MediaTypeManifestV2      = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeManifestListV2  = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeOCIManifest     = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex        = "application/vnd.oci.image.index.v1+json"
)

// Manifest is a minimal OCI / Docker manifest structure.
// We only care about the fields needed for policy evaluation.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config,omitempty"`
	Layers        []Descriptor      `json:"layers,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	// Manifests is populated for manifest lists / OCI indexes.
	Manifests []ManifestRef `json:"manifests,omitempty"`
}

type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Size        int64             `json:"size"`
	Digest      string            `json:"digest"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ManifestRef struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

type Platform struct {
	OS           string   `json:"os"`
	Architecture string   `json:"architecture"`
	Variant      string   `json:"variant,omitempty"`
	OSFeatures   []string `json:"os.features,omitempty"`
}

func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// ToPackageFacts converts a manifest + image reference to PackageFacts.
// The OCI standard annotations are the primary source of trust signals.
func (m *Manifest) ToPackageFacts(imageName, reference string) *facts.PackageFacts {
	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemDocker,
		Name:      imageName,
		Version:   reference,
	}

	if m.Annotations != nil {
		// Published time from OCI annotation.
		if created, ok := m.Annotations["org.opencontainers.image.created"]; ok {
			if t, err := time.Parse(time.RFC3339, created); err == nil {
				pf.PublishedAt = t
				pf.AgeDays = time.Since(t).Hours() / 24
			}
		}
	}

	pf.Trust = extractTrust(imageName, m)
	return pf
}

// extractTrust builds TrustSignals from OCI manifest metadata.
func extractTrust(imageName string, m *Manifest) *facts.TrustSignals {
	t := &facts.TrustSignals{}

	// Determine publisher from image name convention:
	// "library/ubuntu" → official Docker Hub image → TrustTrustedPublisher
	// "nginx" (no slash) → also official library image
	// "myorg/myimage"   → user/org image → TrustUser
	publisherLevel := facts.TrustUser
	if isOfficialImage(imageName) {
		publisherLevel = facts.TrustTrustedPublisher
	}
	t.Publisher = &facts.PublisherSignal{
		ID:    publisherOrgFromName(imageName),
		Level: publisherLevel,
	}

	// Check for cosign / sigstore provenance via OCI annotations.
	if m.Annotations != nil {
		// buildkit/SLSA provenance attestation reference.
		_, hasBuildkit := m.Annotations["vnd.docker.buildkit.ref.name"]
		_, hasSLSA := m.Annotations["in-toto.io/predicate-type"]
		_, hasOCISource := m.Annotations["org.opencontainers.image.source"]

		if hasBuildkit || hasSLSA {
			t.Provenance = &facts.ProvenanceSignal{
				Present:  true,
				Verified: hasSLSA, // SLSA predicate means attestation was verified
			}
			if src := m.Annotations["org.opencontainers.image.source"]; src != "" {
				t.Provenance.SourceRepo = src
			}
		} else if hasOCISource {
			// Source annotation exists but no provenance — still useful signal.
			t.Provenance = &facts.ProvenanceSignal{
				Present:  false,
				SourceRepo: m.Annotations["org.opencontainers.image.source"],
			}
		}
	}

	return t
}

func isOfficialImage(name string) bool {
	// Docker Hub official images are in the "library" namespace or have no slash.
	if name == "library" {
		return true
	}
	if idx := indexOf(name, '/'); idx < 0 {
		return true // top-level name, implicitly library/
	} else {
		org := name[:idx]
		return org == "library"
	}
}

func publisherOrgFromName(name string) string {
	if idx := indexOf(name, '/'); idx >= 0 {
		return name[:idx]
	}
	return "library"
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
