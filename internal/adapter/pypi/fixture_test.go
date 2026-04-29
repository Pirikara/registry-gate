package pypi_test

// Fixture tests parse raw JSON that matches the real PyPI registry and PEP 740
// endpoint format (using dummy package names) to verify struct field mappings
// and timestamp parsing are correct.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/pirikara/registory-gate/internal/adapter/pypi"
	"github.com/pirikara/registory-gate/internal/facts"
)

func readPyPIFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// pypi-basic-with-microsec-ts.json — PyPI JSON API format:
//   - upload_time_iso_8601 with microseconds ("2023-05-22T15:12:34.103116Z")
//   - upload_time without timezone ("2023-05-22T15:12:34")
//   - multiple release files (wheel + sdist)
func TestFixture_PyPI_Basic(t *testing.T) {
	resp, err := pypi.ParseJSONAPI(readPyPIFixture(t, "pypi-basic-with-microsec-ts.json"))
	if err != nil {
		t.Fatalf("ParseJSONAPI: %v", err)
	}

	if resp.Info.Name != "dummy-http" {
		t.Errorf("name: got %q", resp.Info.Name)
	}
	if resp.Info.Version != "2.31.0" {
		t.Errorf("version: got %q", resp.Info.Version)
	}
	if resp.Info.Yanked {
		t.Error("yanked should be false")
	}

	files := resp.Releases["2.31.0"]
	if len(files) != 2 {
		t.Fatalf("expected 2 release files, got %d", len(files))
	}
}

// upload_time_iso_8601 with microseconds must parse correctly.
func TestFixture_PyPI_MicrosecondTimestamp(t *testing.T) {
	resp, _ := pypi.ParseJSONAPI(readPyPIFixture(t, "pypi-basic-with-microsec-ts.json"))

	pf, err := resp.ToPackageFacts("2.31.0")
	if err != nil {
		t.Fatalf("ToPackageFacts: %v", err)
	}

	if pf.PublishedAt.IsZero() {
		t.Fatal("PublishedAt is zero: PyPI timestamps with microseconds (.103116Z) failed to parse")
	}
	// "upload_time_iso_8601": "2023-05-22T15:12:34.103116Z"
	if pf.PublishedAt.Year() != 2023 || pf.PublishedAt.Month() != 5 || pf.PublishedAt.Day() != 22 {
		t.Errorf("PublishedAt date: got %v, want 2023-05-22", pf.PublishedAt)
	}
}

// upload_time (no timezone, T separator) is the fallback when upload_time_iso_8601 is absent.
func TestFixture_PyPI_UploadTime_NoTimezone_Fallback(t *testing.T) {
	resp := &pypi.JSONAPIResponse{
		Info: pypi.PackageInfo{Name: "dummy-pkg", Version: "1.0.0"},
		Releases: map[string][]pypi.ReleaseFile{
			"1.0.0": {{
				Filename:   "dummy_pkg-1.0.0.tar.gz",
				URL:        "https://files.pythonhosted.org/packages/dummy_pkg-1.0.0.tar.gz",
				UploadTime: "2022-06-15T08:00:00",
				// UploadTimeISO intentionally empty
			}},
		},
	}
	pf, err := resp.ToPackageFacts("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if pf.PublishedAt.IsZero() {
		t.Fatal("PublishedAt is zero: upload_time without timezone failed to parse")
	}
	if pf.PublishedAt.Year() != 2022 || pf.PublishedAt.Month() != 6 || pf.PublishedAt.Day() != 15 {
		t.Errorf("upload_time fallback: got %v, want 2022-06-15", pf.PublishedAt)
	}
}

// PrimaryFilename should return the wheel file when both wheel and sdist are present.
func TestFixture_PyPI_PrimaryFilename_PrefersWheel(t *testing.T) {
	resp, _ := pypi.ParseJSONAPI(readPyPIFixture(t, "pypi-basic-with-microsec-ts.json"))

	got := resp.PrimaryFilename("2.31.0")
	if got != "dummy_http-2.31.0-py3-none-any.whl" {
		t.Errorf("PrimaryFilename: got %q, want wheel", got)
	}
}

// pep740-bundle.json — PEP 740 provenance bundle format.
func TestFixture_PyPI_PEP740Bundle(t *testing.T) {
	raw := readPyPIFixture(t, "pep740-bundle.json")

	var bundle pypi.PEP740Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("unmarshal PEP740Bundle: %v", err)
	}

	if bundle.Version != 1 {
		t.Errorf("version: got %d, want 1", bundle.Version)
	}
	if len(bundle.AttestationBundles) != 1 {
		t.Fatalf("attestation_bundles: got %d, want 1", len(bundle.AttestationBundles))
	}

	pub := bundle.AttestationBundles[0].Publisher
	if pub == nil {
		t.Fatal("publisher should not be nil")
	}
	if pub.Kind != "GitHub" {
		t.Errorf("publisher.kind: got %q, want 'GitHub'", pub.Kind)
	}
	if pub.Repository != "example-org/dummy-http" {
		t.Errorf("publisher.repository: got %q, want 'example-org/dummy-http'", pub.Repository)
	}
	if pub.Workflow != "publish.yml" {
		t.Errorf("publisher.workflow: got %q", pub.Workflow)
	}

	// ToTrustSignals must produce TrustTrustedPublisher from a PEP 740 bundle.
	ts := bundle.ToTrustSignals()
	if ts == nil || ts.Publisher == nil {
		t.Fatal("expected publisher trust signal from PEP 740 bundle")
	}
	if ts.Publisher.Level != facts.TrustTrustedPublisher {
		t.Errorf("publisher level: got %v, want TrustTrustedPublisher", ts.Publisher.Level)
	}
	if ts.Publisher.ID != "example-org/dummy-http" {
		t.Errorf("publisher ID should be repository, got %q", ts.Publisher.ID)
	}
	if ts.Provenance == nil || !ts.Provenance.Present || !ts.Provenance.Verified {
		t.Error("provenance should be present and verified from PEP 740 bundle")
	}
}
