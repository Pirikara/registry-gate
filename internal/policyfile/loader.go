// Package policyfile loads YAML policy definitions from disk and converts
// them into runtime policy entries. Kept separate from internal/policy to
// avoid an import cycle (policy/rules imports policy).
package policyfile

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

// Loaded holds the parsed policy along with its source metadata.
type Loaded struct {
	Source  string
	Version int
	Entries []policy.Entry
}

// LoadFromFile reads a YAML policy file and returns a Loaded result.
// If path is empty, returns an empty (allow-all) policy set.
func LoadFromFile(path string) (*Loaded, error) {
	if path == "" {
		return &Loaded{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}
	loaded, err := parsePolicyYAML(raw)
	if err != nil {
		return nil, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	loaded.Source = path
	return loaded, nil
}

// yamlDoc mirrors the on-disk YAML structure.
//
//	version: 1
//	ecosystems:
//	  - package-ecosystem: pypi
//	    allow: [django]
//	    deny: [bad-package]
//	    cooldown:
//	      default-days: 7
//	      include: ["*"]
//	      exclude: [internal-*]
type yamlDoc struct {
	Version    int                   `yaml:"version"`
	Ecosystems []yamlEcosystemPolicy `yaml:"ecosystems"`
}

type yamlEcosystemPolicy struct {
	PackageEcosystem string              `yaml:"package-ecosystem"`
	Allow            []string            `yaml:"allow,omitempty"`
	Deny             []string            `yaml:"deny,omitempty"`
	Cooldown         *yamlCooldown       `yaml:"cooldown,omitempty"`
	MinDownloads     *yamlMinDownloads   `yaml:"min-downloads,omitempty"`
	TrustDowngrade   *yamlTrustDowngrade `yaml:"trust-downgrade,omitempty"`
}

type yamlCooldown struct {
	DefaultDays     float64  `yaml:"default-days"`
	Include         []string `yaml:"include,omitempty"`
	Exclude         []string `yaml:"exclude,omitempty"`
	SemverMajorDays *float64 `yaml:"semver-major-days,omitempty"`
	SemverMinorDays *float64 `yaml:"semver-minor-days,omitempty"`
	SemverPatchDays *float64 `yaml:"semver-patch-days,omitempty"`
}

type yamlMinDownloads struct {
	Threshold int64    `yaml:"threshold"`
	Include   []string `yaml:"include,omitempty"`
	Exclude   []string `yaml:"exclude,omitempty"`
}

type yamlTrustDowngrade struct {
	Watch     []string `yaml:"watch"`
	OnUnknown string   `yaml:"on-unknown,omitempty"`
	Include   []string `yaml:"include,omitempty"`
	Exclude   []string `yaml:"exclude,omitempty"`
}

func parsePolicyYAML(raw []byte) (*Loaded, error) {
	var doc yamlDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}

	out := &Loaded{Version: doc.Version}
	if doc.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", doc.Version)
	}
	if len(doc.Ecosystems) == 0 {
		return nil, fmt.Errorf("version 1 requires ecosystems")
	}
	for i, ecoPolicy := range doc.Ecosystems {
		entries, err := toEcosystemEntries(ecoPolicy)
		if err != nil {
			return nil, fmt.Errorf("ecosystems[%d]: %w", i, err)
		}
		out.Entries = append(out.Entries, entries...)
	}
	return out, nil
}

func toEcosystemEntries(in yamlEcosystemPolicy) ([]policy.Entry, error) {
	eco, err := parsePackageEcosystem(in.PackageEcosystem)
	if err != nil {
		return nil, err
	}

	var out []policy.Entry
	if len(in.Allow) > 0 {
		patterns, err := ecosystemPatterns(eco, in.Allow)
		if err != nil {
			return nil, fmt.Errorf("allow: %w", err)
		}
		out = append(out, policy.Entry{
			Match: matchForPatterns(eco, patterns, nil),
			Rule:  rules.NewAllowPatterns(ecosystemRuleID(eco, "allow"), patterns),
		})
	}
	if len(in.Deny) > 0 {
		patterns, err := ecosystemPatterns(eco, in.Deny)
		if err != nil {
			return nil, fmt.Errorf("deny: %w", err)
		}
		out = append(out, policy.Entry{
			Match: matchForPatterns(eco, patterns, nil),
			Rule:  rules.NewDenyPatterns(ecosystemRuleID(eco, "deny"), patterns),
		})
	}
	if in.Cooldown != nil {
		entry, err := cooldownEntry(eco, in.Cooldown)
		if err != nil {
			return nil, fmt.Errorf("cooldown: %w", err)
		}
		out = append(out, entry)
	}
	if in.MinDownloads != nil {
		entry, err := minDownloadsEntry(eco, in.MinDownloads)
		if err != nil {
			return nil, fmt.Errorf("min-downloads: %w", err)
		}
		out = append(out, entry)
	}
	if in.TrustDowngrade != nil {
		entry, err := trustDowngradeEntry(eco, in.TrustDowngrade)
		if err != nil {
			return nil, fmt.Errorf("trust-downgrade: %w", err)
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("entry has no policy settings")
	}
	return out, nil
}

func parsePackageEcosystem(s string) (facts.Ecosystem, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm":
		return facts.EcosystemNPM, nil
	case "pip", "pypi":
		return facts.EcosystemPyPI, nil
	case "bundler", "rubygems":
		return facts.EcosystemRubyGems, nil
	case "composer":
		return facts.EcosystemComposer, nil
	case "docker":
		return facts.EcosystemDocker, nil
	case "brew", "homebrew":
		return facts.EcosystemHomebrew, nil
	case "maven", "gradle":
		return facts.EcosystemMaven, nil
	case "nuget":
		return facts.EcosystemNuGet, nil
	case "cargo", "crates", "crates.io":
		return facts.EcosystemCargo, nil
	case "go", "gomod", "go-modules":
		return facts.EcosystemGoMod, nil
	case "":
		return "", fmt.Errorf("package-ecosystem is required")
	default:
		return "", fmt.Errorf("unsupported package-ecosystem %q", s)
	}
}

func ecosystemPatterns(eco facts.Ecosystem, patterns []string) ([]policy.PackagePattern, error) {
	out := make([]policy.PackagePattern, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("package pattern cannot be empty")
		}
		out = append(out, policy.PackagePattern{Ecosystem: eco, Pattern: p})
	}
	return out, nil
}

func matchForPatterns(eco facts.Ecosystem, include, exclude []policy.PackagePattern) policy.Match {
	return policy.Match{
		Ecosystems:             []facts.Ecosystem{eco},
		PackagePatterns:        include,
		ExcludePackagePatterns: exclude,
	}
}

func cooldownEntry(eco facts.Ecosystem, in *yamlCooldown) (policy.Entry, error) {
	if in.SemverMajorDays != nil || in.SemverMinorDays != nil || in.SemverPatchDays != nil {
		return policy.Entry{}, fmt.Errorf("semver cooldown fields are not supported")
	}
	days := in.DefaultDays
	if days <= 0 {
		return policy.Entry{}, fmt.Errorf("default-days must be > 0")
	}
	include, err := ecosystemPatterns(eco, in.Include)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("include: %w", err)
	}
	exclude, err := ecosystemPatterns(eco, in.Exclude)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("exclude: %w", err)
	}
	return policy.Entry{
		Match: matchForPatterns(eco, include, exclude),
		Rule:  rules.NewCooldown(ecosystemRuleID(eco, "cooldown"), days),
	}, nil
}

func minDownloadsEntry(eco facts.Ecosystem, in *yamlMinDownloads) (policy.Entry, error) {
	if in.Threshold <= 0 {
		return policy.Entry{}, fmt.Errorf("threshold must be > 0")
	}
	include, err := ecosystemPatterns(eco, in.Include)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("include: %w", err)
	}
	exclude, err := ecosystemPatterns(eco, in.Exclude)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("exclude: %w", err)
	}
	return policy.Entry{
		Match: matchForPatterns(eco, include, exclude),
		Rule:  rules.NewMinDownloads(ecosystemRuleID(eco, "min-downloads"), in.Threshold),
	}, nil
}

func trustDowngradeEntry(eco facts.Ecosystem, in *yamlTrustDowngrade) (policy.Entry, error) {
	include, err := ecosystemPatterns(eco, in.Include)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("include: %w", err)
	}
	exclude, err := ecosystemPatterns(eco, in.Exclude)
	if err != nil {
		return policy.Entry{}, fmt.Errorf("exclude: %w", err)
	}
	watch := make([]rules.TrustDowngradeWatch, 0, len(in.Watch))
	for _, w := range in.Watch {
		tw, ok := parseTrustWatch(w)
		if !ok {
			return policy.Entry{}, fmt.Errorf("unknown watch field %q", w)
		}
		watch = append(watch, tw)
	}
	ou, err := parseOnUnknown(in.OnUnknown)
	if err != nil {
		return policy.Entry{}, err
	}
	return policy.Entry{
		Match: matchForPatterns(eco, include, exclude),
		Rule:  rules.NewTrustDowngrade(ecosystemRuleID(eco, "trust-downgrade"), watch, ou),
	}, nil
}

func ecosystemRuleID(eco facts.Ecosystem, kind string) string {
	return fmt.Sprintf("%s/%s", eco, kind)
}

func parseTrustWatch(s string) (rules.TrustDowngradeWatch, bool) {
	switch s {
	case "provenance.present":
		return rules.WatchProvenancePresent, true
	case "provenance.verified":
		return rules.WatchProvenanceVerified, true
	case "publisher.type":
		return rules.WatchPublisherType, true
	case "publisher.id":
		return rules.WatchPublisherID, true
	case "publisher.two_factor":
		return rules.WatchPublisherTwoFactor, true
	case "signature.present":
		return rules.WatchSignaturePresent, true
	case "signature.verified":
		return rules.WatchSignatureVerified, true
	}
	return "", false
}

func parseOnUnknown(s string) (rules.OnUnknown, error) {
	switch s {
	case "", "warn":
		return rules.OnUnknownWarn, nil
	case "block":
		return rules.OnUnknownBlock, nil
	case "ignore":
		return rules.OnUnknownIgnore, nil
	}
	return "", fmt.Errorf("invalid on-unknown: %q", s)
}
