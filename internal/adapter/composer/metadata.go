package composer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
)

// P2Metadata is the Composer 2 per-package metadata response served from
// /p2/{vendor}/{package}.json. It keeps the original JSON object so unknown
// Composer fields are preserved when the response is filtered and rewritten.
type P2Metadata struct {
	Raw      map[string]any
	Packages map[string][]*PackageVersion
}

type PackageVersion struct {
	Raw map[string]any
}

func ParseP2Metadata(data []byte) (*P2Metadata, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parse composer p2 metadata: %w", err)
	}

	packagesObj, ok := raw["packages"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("composer p2 metadata missing packages object")
	}

	meta := &P2Metadata{
		Raw:      raw,
		Packages: make(map[string][]*PackageVersion, len(packagesObj)),
	}
	minified, _ := raw["minified"].(string)

	for name, versionsAny := range packagesObj {
		versionsList, ok := versionsAny.([]any)
		if !ok {
			return nil, fmt.Errorf("composer p2 metadata package %s is not a version list", name)
		}

		versions := make([]map[string]any, 0, len(versionsList))
		for _, item := range versionsList {
			obj, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("composer p2 metadata package %s contains non-object version", name)
			}
			versions = append(versions, obj)
		}
		if minified == "composer/2.0" {
			versions = expandMinifiedVersions(versions)
		}

		out := make([]*PackageVersion, 0, len(versions))
		for _, v := range versions {
			out = append(out, &PackageVersion{Raw: v})
		}
		meta.Packages[name] = out
	}

	// Once expanded, emit normal p2 metadata. Composer accepts unminified lists,
	// and this keeps filtering safe even when the first version was removed.
	if minified == "composer/2.0" {
		delete(meta.Raw, "minified")
		meta.syncPackages()
	}

	return meta, nil
}

func (m *P2Metadata) Encode() ([]byte, error) {
	m.syncPackages()
	return json.Marshal(m.Raw)
}

func (m *P2Metadata) syncPackages() {
	packages := make(map[string]any, len(m.Packages))
	for name, versions := range m.Packages {
		rawVersions := make([]any, 0, len(versions))
		for _, v := range versions {
			rawVersions = append(rawVersions, v.Raw)
		}
		packages[name] = rawVersions
	}
	m.Raw["packages"] = packages
}

func expandMinifiedVersions(versions []map[string]any) []map[string]any {
	expanded := make([]map[string]any, 0, len(versions))
	var previous map[string]any
	for _, version := range versions {
		if previous == nil {
			previous = cloneMap(version)
			expanded = append(expanded, previous)
			continue
		}

		next := cloneMap(previous)
		for key, val := range version {
			if s, ok := val.(string); ok && s == "__unset" {
				delete(next, key)
				continue
			}
			next[key] = val
		}
		previous = next
		expanded = append(expanded, next)
	}
	return expanded
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (v *PackageVersion) Name(defaultName string) string {
	if name, ok := v.Raw["name"].(string); ok && name != "" {
		return name
	}
	return defaultName
}

func (v *PackageVersion) Version() string {
	if version, ok := v.Raw["version"].(string); ok {
		return version
	}
	if version, ok := v.Raw["version_normalized"].(string); ok {
		return version
	}
	return ""
}

func (v *PackageVersion) ToPackageFacts(defaultName string) *facts.PackageFacts {
	pf := &facts.PackageFacts{
		Ecosystem:    facts.EcosystemComposer,
		Name:         v.Name(defaultName),
		Version:      v.Version(),
		IsDeprecated: isAbandoned(v.Raw["abandoned"]),
	}

	if ts, ok := v.Raw["time"].(string); ok && ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			pf.PublishedAt = t
			pf.AgeDays = time.Since(t).Hours() / 24
		} else if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
			pf.PublishedAt = t
			pf.AgeDays = time.Since(t).Hours() / 24
		}
	}

	return pf
}

func isAbandoned(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val != "" && val != "false"
	default:
		return false
	}
}

func (v *PackageVersion) RewriteDownloadURLs(proxyBaseURL string) {
	dist, ok := v.Raw["dist"].(map[string]any)
	if !ok {
		return
	}
	orig, ok := dist["url"].(string)
	if !ok || orig == "" {
		return
	}

	dist["url"] = BuildDistProxyURL(proxyBaseURL, v.Name(""), v.Version(), orig)
	delete(v.Raw, "source")
}

func BuildDistProxyURL(proxyBaseURL, packageName, version, upstreamURL string) string {
	base := strings.TrimRight(proxyBaseURL, "/")
	filename := distFilename(packageName, version, upstreamURL)
	q := url.Values{}
	q.Set("package", packageName)
	q.Set("version", version)
	q.Set("url", encodeUpstreamURL(upstreamURL))
	return base + "/composer/dist/" + url.PathEscape(filename) + "?" + q.Encode()
}

func distFilename(packageName, version, upstreamURL string) string {
	if u, err := url.Parse(upstreamURL); err == nil {
		base := path.Base(u.Path)
		if base != "." && base != "/" && base != "" {
			return base
		}
	}
	name := strings.ReplaceAll(packageName, "/", "-")
	if name == "" {
		name = "package"
	}
	if version == "" {
		return name + ".zip"
	}
	return name + "-" + version + ".zip"
}
