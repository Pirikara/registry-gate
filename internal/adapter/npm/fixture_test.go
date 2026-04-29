package npm_test

// Fixture tests parse raw JSON that matches the real npm registry response
// format (using dummy package names) to verify struct field mappings, JSON
// tags, and timestamp parsing are correct.
// These complement the unit tests in metadata_test.go which only exercise
// the Go struct → JSON → struct round-trip.

import (
	"os"
	"testing"
	"time"

	"github.com/pirikara/registory-gate/internal/adapter/npm"
	"github.com/pirikara/registory-gate/internal/facts"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// npm-basic-with-millisec-ts.json — npm format: millisecond timestamp, deprecated=false (bool)
func TestFixture_NPM_Basic(t *testing.T) {
	meta, err := npm.ParseMetadata(readFixture(t, "npm-basic-with-millisec-ts.json"))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}

	if meta.Name != "dummy-util" {
		t.Errorf("name: got %q, want 'dummy-util'", meta.Name)
	}
	if meta.DistTags["latest"] != "4.17.21" {
		t.Errorf("dist-tags.latest: got %q", meta.DistTags["latest"])
	}

	pf, err := meta.ToPackageFacts("4.17.21")
	if err != nil {
		t.Fatalf("ToPackageFacts: %v", err)
	}

	// Timestamp with milliseconds must parse correctly — PublishedAt must not be zero.
	if pf.PublishedAt.IsZero() {
		t.Fatal("PublishedAt is zero: npm timestamps with milliseconds (.100Z) failed to parse")
	}
	if pf.PublishedAt.Year() != 2021 {
		t.Errorf("PublishedAt year: got %d, want 2021", pf.PublishedAt.Year())
	}

	// deprecated=false (JSON boolean) must be treated as not deprecated.
	if pf.IsDeprecated {
		t.Error("IsDeprecated should be false when deprecated=false (boolean)")
	}

	// Publisher should be TrustUser (no attestations).
	if pf.Trust == nil || pf.Trust.Publisher == nil {
		t.Fatal("expected publisher trust signal")
	}
	if pf.Trust.Publisher.ID != "testuser" {
		t.Errorf("publisher ID: got %q, want 'testuser'", pf.Trust.Publisher.ID)
	}
	if pf.Trust.Publisher.Level != facts.TrustUser {
		t.Errorf("publisher level: got %v, want TrustUser", pf.Trust.Publisher.Level)
	}
	if pf.Trust.Provenance != nil {
		t.Error("expected no provenance signal for package without attestations")
	}
}

// pkg-with-provenance.json — npm provenance fields and sourceRepository mapping
func TestFixture_NPM_WithProvenance(t *testing.T) {
	meta, err := npm.ParseMetadata(readFixture(t, "pkg-with-provenance.json"))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}

	pf, err := meta.ToPackageFacts("1.0.0")
	if err != nil {
		t.Fatalf("ToPackageFacts: %v", err)
	}

	if pf.Trust == nil || pf.Trust.Provenance == nil {
		t.Fatal("expected provenance trust signal")
	}
	if !pf.Trust.Provenance.Present {
		t.Error("provenance.present should be true")
	}
	if !pf.Trust.Provenance.Verified {
		t.Error("provenance.verified should be true when builderId is set")
	}
	// sourceRepository JSON field must map to SourceRepo.
	want := "https://github.com/example-org/dummy-provenance-pkg"
	if pf.Trust.Provenance.SourceRepo != want {
		t.Errorf("sourceRepository mapping: got %q, want %q", pf.Trust.Provenance.SourceRepo, want)
	}
	if pf.Trust.Publisher == nil || pf.Trust.Publisher.Level != facts.TrustTrustedPublisher {
		t.Errorf("publisher level: got %v, want TrustTrustedPublisher", pf.Trust.Publisher.Level)
	}
}

// pkg-deprecated-string.json — deprecated field as a string message
func TestFixture_NPM_DeprecatedString(t *testing.T) {
	meta, err := npm.ParseMetadata(readFixture(t, "pkg-deprecated-string.json"))
	if err != nil {
		t.Fatalf("ParseMetadata: %v", err)
	}

	pf, err := meta.ToPackageFacts("2.88.2")
	if err != nil {
		t.Fatalf("ToPackageFacts: %v", err)
	}

	if !pf.IsDeprecated {
		t.Error("IsDeprecated should be true when deprecated contains a deprecation message")
	}
}

// Millisecond precision in the npm "time" map must be parsed correctly.
// The real npm registry uses ".100Z" style timestamps.
func TestFixture_NPM_MillisecondTimestamp(t *testing.T) {
	meta, _ := npm.ParseMetadata(readFixture(t, "npm-basic-with-millisec-ts.json"))
	pf, _ := meta.ToPackageFacts("4.17.21")

	// "4.17.21": "2021-10-19T01:01:01.100Z"
	want := time.Date(2021, 10, 19, 1, 1, 1, 100_000_000, time.UTC)
	if !pf.PublishedAt.Equal(want) {
		t.Errorf("millisecond precision: got %v, want %v", pf.PublishedAt, want)
	}
}
