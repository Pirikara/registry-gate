package pypi_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/adapter/pypi"
	"github.com/pirikara/registry-gate/internal/facts"
)

func sampleResponse() *pypi.JSONAPIResponse {
	uploadTime := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	return &pypi.JSONAPIResponse{
		Info: pypi.PackageInfo{
			Name:    "requests",
			Version: "2.31.0",
		},
		Releases: map[string][]pypi.ReleaseFile{
			"2.31.0": {
				{
					Filename:      "requests-2.31.0-py3-none-any.whl",
					URL:           "https://files.pythonhosted.org/packages/requests-2.31.0.whl#sha256=abcdef",
					PackageType:   "bdist_wheel",
					UploadTimeISO: uploadTime,
				},
			},
		},
	}
}

func TestParseJSONAPI_Valid(t *testing.T) {
	raw, _ := json.Marshal(sampleResponse())
	resp, err := pypi.ParseJSONAPI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Info.Name != "requests" {
		t.Errorf("expected name=requests, got %s", resp.Info.Name)
	}
}

func TestParseJSONAPI_Invalid(t *testing.T) {
	_, err := pypi.ParseJSONAPI([]byte("{bad json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestToPackageFacts_Basic(t *testing.T) {
	resp := sampleResponse()
	pf, err := resp.ToPackageFacts("2.31.0")
	if err != nil {
		t.Fatal(err)
	}
	if pf.Ecosystem != facts.EcosystemPyPI {
		t.Error("expected pypi ecosystem")
	}
	if pf.AgeDays < 29 || pf.AgeDays > 31 {
		t.Errorf("expected ~30 days age, got %.1f", pf.AgeDays)
	}
	if pf.Trust != nil {
		t.Error("Trust should not be set by ToPackageFacts; adapter fetches it separately")
	}
}

func TestToPackageFacts_VersionNotFound(t *testing.T) {
	resp := sampleResponse()
	_, err := resp.ToPackageFacts("9.9.9")
	if err == nil {
		t.Error("expected error for missing version")
	}
}

func TestToPackageFacts_Yanked(t *testing.T) {
	resp := sampleResponse()
	resp.Info.Yanked = true
	pf, err := resp.ToPackageFacts("2.31.0")
	if err != nil {
		t.Fatal(err)
	}
	if !pf.Yanked {
		t.Error("expected yanked=true")
	}
}

func TestPrimaryFilename_PrefersWheel(t *testing.T) {
	resp := &pypi.JSONAPIResponse{
		Releases: map[string][]pypi.ReleaseFile{
			"1.0.0": {
				{Filename: "foo-1.0.0.tar.gz"},
				{Filename: "foo-1.0.0-py3-none-any.whl"},
			},
		},
	}
	if got := resp.PrimaryFilename("1.0.0"); got != "foo-1.0.0-py3-none-any.whl" {
		t.Errorf("expected wheel, got %s", got)
	}
}

func TestPrimaryFilename_FallbackToFirst(t *testing.T) {
	resp := &pypi.JSONAPIResponse{
		Releases: map[string][]pypi.ReleaseFile{
			"1.0.0": {{Filename: "foo-1.0.0.tar.gz"}},
		},
	}
	if got := resp.PrimaryFilename("1.0.0"); got != "foo-1.0.0.tar.gz" {
		t.Errorf("expected sdist, got %s", got)
	}
}

func TestPEP740Bundle_ToTrustSignals_WithPublisher(t *testing.T) {
	b := &pypi.PEP740Bundle{
		Version: 1,
		AttestationBundles: []pypi.AttestationBundle{{
			Publisher: &pypi.PEP740Publisher{
				Kind:       "GitHub",
				Repository: "psf/requests",
				Workflow:   "publish.yml",
			},
		}},
	}
	t1 := b.ToTrustSignals()
	if t1.Provenance == nil || !t1.Provenance.Present || !t1.Provenance.Verified {
		t.Error("expected provenance present + verified")
	}
	if t1.Provenance.SourceRepo != "psf/requests" {
		t.Errorf("expected source repo psf/requests, got %s", t1.Provenance.SourceRepo)
	}
	if t1.Publisher == nil || t1.Publisher.Level != facts.TrustTrustedPublisher {
		t.Error("expected publisher trusted_publisher")
	}
}

func TestPEP740Bundle_ToTrustSignals_NoPublisher(t *testing.T) {
	b := &pypi.PEP740Bundle{Version: 1, AttestationBundles: []pypi.AttestationBundle{{}}}
	t1 := b.ToTrustSignals()
	if t1.Provenance == nil || !t1.Provenance.Present {
		t.Error("expected provenance present even without publisher")
	}
	if t1.Publisher != nil {
		t.Error("expected publisher nil when bundle has no publisher")
	}
}

func TestNoProvenanceTrust(t *testing.T) {
	tr := pypi.NoProvenanceTrust()
	if tr.Provenance == nil || tr.Provenance.Present {
		t.Error("expected provenance.present=false")
	}
	if tr.Publisher == nil || tr.Publisher.Level != facts.TrustUser {
		t.Error("expected publisher level=user")
	}
}
