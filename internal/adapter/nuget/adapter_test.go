package nuget_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/nuget"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestServiceIndexRewritesPackageBaseAddress(t *testing.T) {
	upstream := newNuGetUpstream(t)
	defer upstream.Close()

	r := chi.NewRouter()
	nuget.NewTestAdapter(nuget.Config{
		UpstreamIndexURL: upstream.URL + "/index.json",
		ProxyBase:        "https://proxy.example.com",
		PolicyEng:        denyEngine(facts.EcosystemNuGet, "blocked"),
		Recorder:         history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nuget/v3/index.json", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var body struct {
		Resources []map[string]any `json:"resources"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode service index: %v", err)
	}
	if !hasResource(body.Resources, "PackageBaseAddress/3.0.0", "https://proxy.example.com/nuget/v3-flatcontainer/") {
		t.Fatalf("service index did not rewrite flatcontainer URL: %s", resp.Body.String())
	}
	if !hasResource(body.Resources, "RegistrationsBaseUrl/3.6.0", "https://proxy.example.com/nuget/v3/registration/") {
		t.Fatalf("service index did not rewrite registration URL: %s", resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"clientVersion":"4.3.0-alpha"`) {
		t.Fatalf("service index did not preserve unknown resource fields: %s", resp.Body.String())
	}
}

func TestRegistrationLeafRewritesPackageContent(t *testing.T) {
	upstream := newNuGetUpstream(t)
	defer upstream.Close()

	r := chi.NewRouter()
	nuget.NewTestAdapter(nuget.Config{
		UpstreamIndexURL: upstream.URL + "/index.json",
		ProxyBase:        "https://proxy.example.com",
		PolicyEng:        policy.NewEngine(nil),
		Recorder:         history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nuget/v3/registration/registrygate.fixture.blocked/1.0.0.json", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var leaf struct {
		PackageContent string `json:"packageContent"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &leaf); err != nil {
		t.Fatalf("decode registration leaf: %v", err)
	}
	want := "https://proxy.example.com/nuget/v3-flatcontainer/registrygate.fixture.blocked/1.0.0/registrygate.fixture.blocked.1.0.0.nupkg"
	if leaf.PackageContent != want {
		t.Fatalf("registration leaf packageContent: got %q, want %q", leaf.PackageContent, want)
	}
}

func TestPackageDownloadBlockedByDenyPolicy(t *testing.T) {
	upstream := newNuGetUpstream(t)
	defer upstream.Close()

	r := chi.NewRouter()
	nuget.NewTestAdapter(nuget.Config{
		UpstreamIndexURL: upstream.URL + "/index.json",
		ProxyBase:        "https://proxy.example.com",
		PolicyEng:        denyEngine(facts.EcosystemNuGet, "registrygate.fixture.blocked"),
		Recorder:         history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nuget/v3-flatcontainer/registrygate.fixture.blocked/1.0.0/registrygate.fixture.blocked.1.0.0.nupkg", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func newNuGetUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.ReplaceAll(nugetServiceIndexFixture, "{{BASE}}", base)))
		case "/reg/registrygate.fixture.blocked/1.0.0.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.ReplaceAll(nugetRegistrationLeafFixture, "{{BASE}}", base)))
		case "/flat/registrygate.fixture.blocked/1.0.0/registrygate.fixture.blocked.1.0.0.nupkg":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("nupkg"))
		default:
			http.NotFound(w, r)
		}
	}))
	base = srv.URL
	return srv
}

func denyEngine(eco facts.Ecosystem, pkg string) *policy.Engine {
	return policy.NewEngine([]policy.Entry{{
		Match: policy.Match{PackagePatterns: []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}},
		Rule:  rules.NewDenyPatterns(string(eco)+"/deny", []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}),
	}})
}

func hasResource(resources []map[string]any, typ, id string) bool {
	for _, res := range resources {
		if res["@type"] == typ && res["@id"] == id {
			return true
		}
	}
	return false
}

const nugetServiceIndexFixture = `{
  "version": "3.0.0",
  "resources": [
    {
      "@id": "{{BASE}}/query",
      "@type": "SearchQueryService",
      "comment": "Synthetic search endpoint"
    },
    {
      "@id": "{{BASE}}/reg-semver1/",
      "@type": "RegistrationsBaseUrl/3.0.0",
      "comment": "Synthetic registration base without SemVer 2.0.0 packages"
    },
    {
      "@id": "{{BASE}}/flat/",
      "@type": "PackageBaseAddress/3.0.0",
      "comment": "Synthetic flat-container package content base"
    },
    {
      "@id": "{{BASE}}/reg/",
      "@type": "RegistrationsBaseUrl/3.6.0",
      "clientVersion": "4.3.0-alpha",
      "comment": "Synthetic SemVer 2.0.0 registration base"
    },
    {
      "@id": "{{BASE}}/repository-signatures/index.json",
      "@type": "RepositorySignatures/5.0.0",
      "comment": "Synthetic repository signature discovery endpoint"
    }
  ],
  "@context": {
    "@vocab": "http://schema.nuget.org/services#",
    "comment": "http://www.w3.org/2000/01/rdf-schema#comment"
  }
}`

const nugetRegistrationLeafFixture = `{
  "@id": "{{BASE}}/reg/registrygate.fixture.blocked/1.0.0.json",
  "@type": ["Package", "http://schema.nuget.org/catalog#Permalink"],
  "catalogEntry": "{{BASE}}/catalog/data/2026.01.02.03.04.05/registrygate.fixture.blocked.1.0.0.json",
  "listed": true,
  "packageContent": "{{BASE}}/flat/registrygate.fixture.blocked/1.0.0/registrygate.fixture.blocked.1.0.0.nupkg",
  "published": "2026-01-02T03:04:05.123+00:00",
  "registration": "{{BASE}}/reg/registrygate.fixture.blocked/index.json",
  "@context": {
    "@vocab": "http://schema.nuget.org/schema#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "catalogEntry": {"@type": "@id"},
    "registration": {"@type": "@id"},
    "packageContent": {"@type": "@id"},
    "published": {"@type": "xsd:dateTime"}
  }
}`
