package maven_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/maven"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestArtifactDownloadBlockedByDenyPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", time.Now().Add(-48*time.Hour).UTC().Format(http.TimeFormat))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write([]byte("jar"))
	}))
	defer upstream.Close()

	r := chi.NewRouter()
	maven.NewTestAdapter(maven.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   denyEngine(facts.EcosystemMaven, "dev.registrygate.fixture:demo-lib"),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven2/dev/registrygate/fixture/demo-lib/1.0.0/demo-lib-1.0.0.jar", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestMavenMetadataPassesThroughSchema(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dev/registrygate/fixture/demo-lib/maven-metadata.xml" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(mavenMetadataFixture))
	}))
	defer upstream.Close()

	r := chi.NewRouter()
	maven.NewTestAdapter(maven.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   policy.NewEngine(nil),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/maven2/dev/registrygate/fixture/demo-lib/maven-metadata.xml", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "<groupId>dev.registrygate.fixture</groupId>") ||
		!strings.Contains(resp.Body.String(), "<lastUpdated>20260102030405</lastUpdated>") {
		t.Fatalf("metadata response does not look like Maven metadata: %s", resp.Body.String())
	}
}

func denyEngine(eco facts.Ecosystem, pkg string) *policy.Engine {
	return policy.NewEngine([]policy.Entry{{
		Match: policy.Match{PackagePatterns: []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}},
		Rule:  rules.NewDenyPatterns(string(eco)+"/deny", []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}),
	}})
}

const mavenMetadataFixture = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>dev.registrygate.fixture</groupId>
  <artifactId>demo-lib</artifactId>
  <versioning>
    <latest>1.1.0</latest>
    <release>1.1.0</release>
    <versions>
      <version>1.0.0</version>
      <version>1.1.0</version>
    </versions>
    <lastUpdated>20260102030405</lastUpdated>
  </versioning>
</metadata>`
