package policyfile_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policyfile"
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

func TestLoadFromFile_AllRuleKinds(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: npm
    allow:
      - lodash
    deny:
      - evil-pkg
    cooldown:
      default-days: 1
      include:
        - "*"
    min-downloads:
      threshold: 100
    trust-downgrade:
      watch: [provenance.present, publisher.type]
      on-unknown: warn
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

func TestLoadFromFile_EcosystemCooldown(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: pip
    cooldown:
      default-days: 5
      include:
        - requests
        - pandas*
      exclude:
        - pandas
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != 1 {
		t.Fatalf("expected version 1, got %d", loaded.Version)
	}
	if len(loaded.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded.Entries))
	}
	if loaded.Entries[0].Rule.ID() != "pypi/cooldown" {
		t.Fatalf("expected pypi/cooldown rule id, got %s", loaded.Entries[0].Rule.ID())
	}

	eng := policy.NewEngine(loaded.Entries)
	res, err := eng.Evaluate(context.Background(), facts.PackageFacts{
		Ecosystem:   facts.EcosystemPyPI,
		Name:        "pandas-ext",
		Version:     "1.0.0",
		PublishedAt: time.Now().AddDate(0, 0, -1),
		AgeDays:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionBlock {
		t.Fatalf("expected included young package to block, got %s", res.Decision)
	}

	res, err = eng.Evaluate(context.Background(), facts.PackageFacts{
		Ecosystem:   facts.EcosystemPyPI,
		Name:        "pandas",
		Version:     "1.0.0",
		PublishedAt: time.Now().AddDate(0, 0, -1),
		AgeDays:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected exclude to bypass cooldown, got %s", res.Decision)
	}
}

func TestLoadFromFile_RegistryFamilyAliases(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: gradle
    deny: ["com.acme:bad"]
  - package-ecosystem: go
    deny: ["example.com/bad"]
  - package-ecosystem: crates.io
    deny: ["badcrate"]
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"maven/deny", "gomod/deny", "cargo/deny"}
	if len(loaded.Entries) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(loaded.Entries))
	}
	for i, id := range want {
		if loaded.Entries[i].Rule.ID() != id {
			t.Fatalf("entry %d rule id: got %s, want %s", i, loaded.Entries[i].Rule.ID(), id)
		}
	}
}

func TestLoadFromFile_AllowBypassesCooldown(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: npm
    allow:
      - "@company/*"
    cooldown:
      default-days: 7
      include:
        - "*"
`
	path := writeTemp(t, yaml)
	loaded, err := policyfile.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	eng := policy.NewEngine(loaded.Entries)
	res, err := eng.Evaluate(context.Background(), facts.PackageFacts{
		Ecosystem:   facts.EcosystemNPM,
		Name:        "@company/pkg",
		Version:     "1.0.0",
		PublishedAt: time.Now().AddDate(0, 0, -1),
		AgeDays:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow pattern to bypass cooldown, got %s", res.Decision)
	}
}

func TestLoadFromFile_CooldownRejectsSemverFields(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: pypi
    cooldown:
      default-days: 5
      semver-patch-days: 3
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for unsupported semver cooldown field")
	}
}

func TestLoadFromFile_CooldownRequiresPositiveDefaultDays(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: npm
    cooldown:
      default-days: 0
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for non-positive default-days")
	}
}

func TestLoadFromFile_TrustDowngrade_InvalidWatch(t *testing.T) {
	yaml := `
version: 1
ecosystems:
  - package-ecosystem: npm
    trust-downgrade:
      watch: [bogus.field]
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for invalid watch field")
	}
}

func TestLoadFromFile_RejectsRulesSchema(t *testing.T) {
	yaml := `
version: 1
rules:
  - cooldown:
      min_age_days: 7
`
	path := writeTemp(t, yaml)
	if _, err := policyfile.LoadFromFile(path); err == nil {
		t.Error("expected error for removed rules schema")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	if _, err := policyfile.LoadFromFile("/no/such/file.yaml"); err == nil {
		t.Error("expected error for missing file")
	}
}
