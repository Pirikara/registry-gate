package policyfile_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pirikara/registory-gate/internal/policyfile"
)

func writeTemp(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFromFile_Empty(t *testing.T) {
	loaded, err := policyfile.LoadFromFile("")
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 0 {
		t.Errorf("expected empty entries for empty path, got %d", len(loaded.Entries))
	}
}

func TestLoadFromFile_BasicCooldown(t *testing.T) {
	yaml := `
version: 1
rules:
  - cooldown:
      min_age_days: 7
      ecosystems: [npm]
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].Rule.ID() != "cooldown/0" {
		t.Errorf("expected auto-generated rule id, got %s", loaded.Entries[0].Rule.ID())
	}
	if len(loaded.Entries[0].Match.Ecosystems) != 1 {
		t.Errorf("expected 1 ecosystem in match, got %d", len(loaded.Entries[0].Match.Ecosystems))
	}
}

func TestLoadFromFile_AllRuleKinds(t *testing.T) {
	yaml := `
version: 1
rules:
  - cooldown:
      min_age_days: 1
  - min_downloads:
      threshold: 100
  - allow: [npm:lodash]
  - deny:  [npm:evil-pkg]
  - trust_downgrade:
      watch: [provenance.present, publisher.type]
      on_unknown: warn
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(loaded.Entries))
	}
}

func TestLoadFromFile_PackageShorthand(t *testing.T) {
	yaml := `
rules:
  - allow: [npm:lodash, pypi:requests]
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := loaded.Entries[0].Match.Packages
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "lodash" || string(pkgs[0].Ecosystem) != "npm" {
		t.Errorf("first package: %+v", pkgs[0])
	}
	if pkgs[1].Name != "requests" || string(pkgs[1].Ecosystem) != "pypi" {
		t.Errorf("second package: %+v", pkgs[1])
	}
}

func TestLoadFromFile_PackageShorthand_Invalid(t *testing.T) {
	yaml := `
rules:
  - allow: [lodash]
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for missing 'ecosystem:' prefix")
	}
}

func TestLoadFromFile_CooldownRequiresPositive(t *testing.T) {
	yaml := `
rules:
  - cooldown:
      min_age_days: 0
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for non-positive min_age_days")
	}
}

func TestLoadFromFile_NoRuleKindSet(t *testing.T) {
	yaml := `
rules:
  - {}
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for entry with no rule kind")
	}
}

func TestLoadFromFile_MultipleRuleKindsSet(t *testing.T) {
	yaml := `
rules:
  - cooldown:
      min_age_days: 7
    deny: [npm:evil]
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for entry with multiple kinds set")
	}
}

func TestLoadFromFile_TrustDowngrade_InvalidWatch(t *testing.T) {
	yaml := `
rules:
  - trust_downgrade:
      watch: [bogus.field]
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for invalid watch field")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	if _, err := policyfile.LoadFromFile("/no/such/file.yaml"); err == nil {
		t.Error("expected error for missing file")
	}
}
