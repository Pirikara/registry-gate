// Package policyfile loads YAML policy definitions from disk and converts
// them into runtime policy entries. Kept separate from internal/policy to
// avoid an import cycle (policy/rules imports policy).
package policyfile

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
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
// Schema (flat, declaration-ordered):
//
//	version: 1
//	rules:
//	  - allow: [npm:lodash, npm:react]
//	  - deny:  [npm:example-malicious-pkg]
//	  - cooldown:
//	      min_age_days: 7
//	      ecosystems: [npm, pypi]
//	  - trust_downgrade:
//	      ecosystems: [npm, pypi, rubygems]
//	      watch: [provenance.present, publisher.two_factor]
//	      on_unknown: warn
//	  - min_downloads:
//	      threshold: 1000
//	      ecosystems: [npm]
type yamlDoc struct {
	Version int             `yaml:"version"`
	Rules   []yamlRuleEntry `yaml:"rules"`
}

// yamlRuleEntry uses kind-as-key style: exactly one field must be set per
// entry. The field that is set determines the rule kind.
type yamlRuleEntry struct {
	Allow          []string            `yaml:"allow,omitempty"`
	Deny           []string            `yaml:"deny,omitempty"`
	Cooldown       *yamlCooldown       `yaml:"cooldown,omitempty"`
	MinDownloads   *yamlMinDownloads   `yaml:"min_downloads,omitempty"`
	TrustDowngrade *yamlTrustDowngrade `yaml:"trust_downgrade,omitempty"`
}

// yamlMatch is embedded into rules that need an optional package filter.
// Empty ecosystems / packages = match everything.
type yamlMatch struct {
	Ecosystems []string `yaml:"ecosystems,omitempty"`
	Packages   []string `yaml:"packages,omitempty"`
}

type yamlCooldown struct {
	yamlMatch  `yaml:",inline"`
	MinAgeDays float64 `yaml:"min_age_days"`
}

type yamlMinDownloads struct {
	yamlMatch `yaml:",inline"`
	Threshold int64 `yaml:"threshold"`
}

type yamlTrustDowngrade struct {
	yamlMatch `yaml:",inline"`
	Watch     []string `yaml:"watch"`
	OnUnknown string   `yaml:"on_unknown,omitempty"`
}

// errSkipEntry is returned by toEntry when the entry should be silently ignored
// (e.g. allow: [] — an explicitly empty list is a no-op).
var errSkipEntry = errors.New("skip")

func parsePolicyYAML(raw []byte) (*Loaded, error) {
	var doc yamlDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}

	out := &Loaded{Version: doc.Version}
	for i, entry := range doc.Rules {
		converted, err := toEntry(entry, i)
		if errors.Is(err, errSkipEntry) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out.Entries = append(out.Entries, converted)
	}
	return out, nil
}

func toEntry(e yamlRuleEntry, idx int) (policy.Entry, error) {
	// Detect entries where a key is present but the list is empty:
	// allow: []  or  deny: []  → nil=false, len=0. Silently skip these.
	if e.Allow != nil && len(e.Allow) == 0 {
		return policy.Entry{}, errSkipEntry
	}
	if e.Deny != nil && len(e.Deny) == 0 {
		return policy.Entry{}, errSkipEntry
	}

	set := 0
	if len(e.Allow) > 0 {
		set++
	}
	if len(e.Deny) > 0 {
		set++
	}
	if e.Cooldown != nil {
		set++
	}
	if e.MinDownloads != nil {
		set++
	}
	if e.TrustDowngrade != nil {
		set++
	}
	if set == 0 {
		return policy.Entry{}, fmt.Errorf("entry has no rule kind")
	}
	if set > 1 {
		return policy.Entry{}, fmt.Errorf("entry has multiple rule kinds — exactly one must be set")
	}

	switch {
	case len(e.Allow) > 0:
		refs, err := parsePackageRefs(e.Allow)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("allow: %w", err)
		}
		// allow / deny use the package list itself as their match scope.
		return policy.Entry{
			Match: scopeFromRefs(refs),
			Rule:  rules.NewAllow(autoID("allow", idx), refs),
		}, nil

	case len(e.Deny) > 0:
		refs, err := parsePackageRefs(e.Deny)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("deny: %w", err)
		}
		return policy.Entry{
			Match: scopeFromRefs(refs),
			Rule:  rules.NewDeny(autoID("deny", idx), refs),
		}, nil

	case e.Cooldown != nil:
		if e.Cooldown.MinAgeDays <= 0 {
			return policy.Entry{}, fmt.Errorf("cooldown.min_age_days must be > 0")
		}
		match, err := buildMatch(e.Cooldown.yamlMatch)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("cooldown: %w", err)
		}
		return policy.Entry{
			Match: match,
			Rule:  rules.NewCooldown(autoID("cooldown", idx), e.Cooldown.MinAgeDays),
		}, nil

	case e.MinDownloads != nil:
		if e.MinDownloads.Threshold <= 0 {
			return policy.Entry{}, fmt.Errorf("min_downloads.threshold must be > 0")
		}
		match, err := buildMatch(e.MinDownloads.yamlMatch)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("min_downloads: %w", err)
		}
		return policy.Entry{
			Match: match,
			Rule:  rules.NewMinDownloads(autoID("min_downloads", idx), e.MinDownloads.Threshold),
		}, nil

	case e.TrustDowngrade != nil:
		match, err := buildMatch(e.TrustDowngrade.yamlMatch)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("trust_downgrade: %w", err)
		}
		watch := make([]rules.TrustDowngradeWatch, 0, len(e.TrustDowngrade.Watch))
		for _, w := range e.TrustDowngrade.Watch {
			tw, ok := parseTrustWatch(w)
			if !ok {
				return policy.Entry{}, fmt.Errorf("trust_downgrade: unknown watch field %q", w)
			}
			watch = append(watch, tw)
		}
		ou, err := parseOnUnknown(e.TrustDowngrade.OnUnknown)
		if err != nil {
			return policy.Entry{}, fmt.Errorf("trust_downgrade: %w", err)
		}
		return policy.Entry{
			Match: match,
			Rule:  rules.NewTrustDowngrade(autoID("trust_downgrade", idx), watch, ou),
		}, nil
	}

	return policy.Entry{}, fmt.Errorf("unreachable")
}

// parsePackageRefs converts a list of `ecosystem:name` shorthand strings
// into structured PackageRefs.
func parsePackageRefs(in []string) ([]policy.PackageRef, error) {
	out := make([]policy.PackageRef, 0, len(in))
	for _, s := range in {
		eco, name, ok := strings.Cut(s, ":")
		if !ok || eco == "" || name == "" {
			return nil, fmt.Errorf("package ref %q must be in 'ecosystem:name' form", s)
		}
		out = append(out, policy.PackageRef{
			Ecosystem: facts.Ecosystem(eco),
			Name:      name,
		})
	}
	return out, nil
}

// scopeFromRefs builds a Match where ecosystems/packages are derived from a
// package list. Used by allow/deny so the rule only fires for those packages.
func scopeFromRefs(refs []policy.PackageRef) policy.Match {
	return policy.Match{Packages: refs}
}

func buildMatch(m yamlMatch) (policy.Match, error) {
	out := policy.Match{}
	for _, e := range m.Ecosystems {
		out.Ecosystems = append(out.Ecosystems, facts.Ecosystem(e))
	}
	if len(m.Packages) > 0 {
		refs, err := parsePackageRefs(m.Packages)
		if err != nil {
			return policy.Match{}, err
		}
		out.Packages = refs
	}
	return out, nil
}

func autoID(kind string, idx int) string {
	return fmt.Sprintf("%s/%d", kind, idx)
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
	return "", fmt.Errorf("invalid on_unknown: %q", s)
}
