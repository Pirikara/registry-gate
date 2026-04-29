package npm_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/adapter/npm"
	"github.com/pirikara/registry-gate/internal/facts"
)

func sampleMeta(provenanceBuilderID string) *npm.RegistryMetadata {
	var attestations *npm.Attestations
	if provenanceBuilderID != "" {
		attestations = &npm.Attestations{
			Provenance: &npm.ProvenanceDetail{
				BuilderID:  provenanceBuilderID,
				SourceRepo: "github.com/lodash/lodash",
			},
		}
	}

	return &npm.RegistryMetadata{
		Name: "lodash",
		Time: map[string]string{
			"4.17.21": time.Now().AddDate(0, 0, -30).Format(time.RFC3339),
		},
		Versions: map[string]*npm.VersionMeta{
			"4.17.21": {
				Name:    "lodash",
				Version: "4.17.21",
				Dist: npm.DistInfo{
					Tarball:   "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
					Integrity: "sha512-abc",
				},
				NPMUser:      &npm.NPMUser{Name: "jdalton"},
				Attestations: attestations,
			},
		},
	}
}

// --- ParseMetadata ---

func TestParseMetadata_Valid(t *testing.T) {
	raw, _ := json.Marshal(sampleMeta(""))
	meta, err := npm.ParseMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "lodash" {
		t.Errorf("expected name=lodash, got %s", meta.Name)
	}
	if _, ok := meta.Versions["4.17.21"]; !ok {
		t.Error("expected version 4.17.21 in versions map")
	}
}

func TestParseMetadata_Invalid(t *testing.T) {
	_, err := npm.ParseMetadata([]byte("not-json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// --- RewriteTarballURLs ---

func TestRewriteTarballURLs(t *testing.T) {
	meta := sampleMeta("")
	meta.RewriteTarballURLs("https://npm.example.com")

	v := meta.Versions["4.17.21"]
	want := "https://npm.example.com/lodash/-/lodash-4.17.21.tgz"
	if v.Dist.Tarball != want {
		t.Errorf("tarball URL mismatch:\n  got:  %s\n  want: %s", v.Dist.Tarball, want)
	}
}

func TestRewriteTarballURLs_TrailingSlash(t *testing.T) {
	meta := sampleMeta("")
	meta.RewriteTarballURLs("https://npm.example.com/")

	v := meta.Versions["4.17.21"]
	if got := v.Dist.Tarball; got != "https://npm.example.com/lodash/-/lodash-4.17.21.tgz" {
		t.Errorf("unexpected tarball URL: %s", got)
	}
}

// --- ToPackageFacts ---

func TestToPackageFacts_Basic(t *testing.T) {
	meta := sampleMeta("")
	pf, err := meta.ToPackageFacts("4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Name != "lodash" {
		t.Errorf("expected name=lodash, got %s", pf.Name)
	}
	if pf.Ecosystem != facts.EcosystemNPM {
		t.Error("expected npm ecosystem")
	}
	if pf.AgeDays < 29 || pf.AgeDays > 31 {
		t.Errorf("expected ~30 days age, got %.1f", pf.AgeDays)
	}
}

func TestToPackageFacts_WithProvenance(t *testing.T) {
	meta := sampleMeta("https://github.com/actions/runner")
	pf, err := meta.ToPackageFacts("4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Trust == nil {
		t.Fatal("expected trust signals to be populated")
	}
	if pf.Trust.Provenance == nil || !pf.Trust.Provenance.Present {
		t.Error("expected provenance.present=true")
	}
	if !pf.Trust.Provenance.Verified {
		t.Error("expected provenance.verified=true when builder ID is set")
	}
	if pf.Trust.Publisher == nil || pf.Trust.Publisher.Level != facts.TrustTrustedPublisher {
		t.Error("expected publisher.level=trusted_publisher when attestations present")
	}
}

func TestToPackageFacts_WithoutProvenance(t *testing.T) {
	meta := sampleMeta("")
	pf, err := meta.ToPackageFacts("4.17.21")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Trust == nil {
		t.Fatal("expected trust signals")
	}
	if pf.Trust.Provenance != nil {
		t.Error("expected provenance=nil when no attestations")
	}
	if pf.Trust.Publisher == nil || pf.Trust.Publisher.Level != facts.TrustUser {
		t.Error("expected publisher.level=user when no attestations")
	}
}

func TestToPackageFacts_VersionNotFound(t *testing.T) {
	meta := sampleMeta("")
	_, err := meta.ToPackageFacts("9.9.9")
	if err == nil {
		t.Error("expected error for non-existent version")
	}
}
