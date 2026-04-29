package rubygems_test

// Fixture tests parse raw JSON that matches the real RubyGems registry format
// (using dummy package names) to verify struct field mappings and timestamp
// parsing are correct.

import (
	"os"
	"testing"

	"github.com/pirikara/registry-gate/internal/adapter/rubygems"
	"github.com/pirikara/registry-gate/internal/facts"
)

func readRubyFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// rubygems-version-list.json — RubyGems version list format:
//   - created_at with milliseconds ("2023-10-04T09:21:56.000Z")
//   - downloads_count field present
func TestFixture_RubyGems_VersionList(t *testing.T) {
	versions, err := rubygems.ParseVersionList(readRubyFixture(t, "rubygems-version-list.json"))
	if err != nil {
		t.Fatalf("ParseVersionList: %v", err)
	}

	if len(versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(versions))
	}

	v := versions[0]
	if v.Number != "7.1.0" {
		t.Errorf("version number: got %q", v.Number)
	}
	if v.Downloads != 12345678 {
		t.Errorf("downloads_count: got %d, want 12345678", v.Downloads)
	}
}

// Millisecond timestamps in created_at must parse correctly.
func TestFixture_RubyGems_MillisecondTimestamp(t *testing.T) {
	versions, _ := rubygems.ParseVersionList(readRubyFixture(t, "rubygems-version-list.json"))

	pf := versions[0].ToPackageFacts("dummy-framework")

	// "created_at": "2023-10-04T09:21:56.000Z"
	if pf.PublishedAt.IsZero() {
		t.Fatal("PublishedAt is zero: RubyGems timestamps with milliseconds (.000Z) failed to parse")
	}
	if pf.PublishedAt.Year() != 2023 || pf.PublishedAt.Month() != 10 || pf.PublishedAt.Day() != 4 {
		t.Errorf("PublishedAt: got %v, want 2023-10-04", pf.PublishedAt)
	}
}

// ToPackageFacts from VersionInfo sets basic fields correctly.
func TestFixture_RubyGems_VersionInfo_Facts(t *testing.T) {
	versions, _ := rubygems.ParseVersionList(readRubyFixture(t, "rubygems-version-list.json"))

	pf := versions[0].ToPackageFacts("dummy-framework")

	if pf.Name != "dummy-framework" {
		t.Errorf("name: got %q", pf.Name)
	}
	if pf.Version != "7.1.0" {
		t.Errorf("version: got %q", pf.Version)
	}
	if pf.Ecosystem != facts.EcosystemRubyGems {
		t.Error("ecosystem should be rubygems")
	}
	if pf.Yanked {
		t.Error("yanked should be false")
	}
}

// rubygems-version-detail.json — RubyGems version detail with rubygems_mfa_required.
func TestFixture_RubyGems_VersionDetail(t *testing.T) {
	vd, err := rubygems.ParseVersionDetail(readRubyFixture(t, "rubygems-version-detail.json"))
	if err != nil {
		t.Fatalf("ParseVersionDetail: %v", err)
	}

	if vd.Name != "dummy-framework" {
		t.Errorf("name: got %q", vd.Name)
	}
	if vd.Number != "7.1.0" {
		t.Errorf("number: got %q", vd.Number)
	}
	if vd.Metadata["rubygems_mfa_required"] != "true" {
		t.Errorf("rubygems_mfa_required: got %q", vd.Metadata["rubygems_mfa_required"])
	}
}

// version_created_at with milliseconds must parse correctly.
func TestFixture_RubyGems_VersionDetail_Timestamp(t *testing.T) {
	vd, _ := rubygems.ParseVersionDetail(readRubyFixture(t, "rubygems-version-detail.json"))
	pf := vd.ToPackageFacts()

	// "version_created_at": "2023-10-04T09:21:56.000Z"
	if pf.PublishedAt.IsZero() {
		t.Fatal("PublishedAt is zero: RubyGems version detail timestamps failed to parse")
	}
}

// 2FA flag from rubygems_mfa_required="true" must propagate to TrustSignals.
func TestFixture_RubyGems_VersionDetail_TwoFactor(t *testing.T) {
	vd, _ := rubygems.ParseVersionDetail(readRubyFixture(t, "rubygems-version-detail.json"))
	pf := vd.ToPackageFacts()

	if pf.Trust == nil || pf.Trust.Publisher == nil {
		t.Fatal("expected publisher trust signal")
	}
	if pf.Trust.Publisher.TwoFactorEnabled == nil {
		t.Fatal("TwoFactorEnabled should not be nil when rubygems_mfa_required=true")
	}
	if !*pf.Trust.Publisher.TwoFactorEnabled {
		t.Error("TwoFactorEnabled should be true")
	}
}
