package gomod_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/gomod"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestZipDownloadBlockedByDenyPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.invalid/registrygate/fixture/@v/v1.0.0.info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(goInfoFixture))
		case "/example.invalid/registrygate/fixture/@v/v1.0.0.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("zip"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	r := chi.NewRouter()
	gomod.NewTestAdapter(gomod.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   denyEngine(facts.EcosystemGoMod, "example.invalid/registrygate/fixture"),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/gomod/example.invalid/registrygate/fixture/@v/v1.0.0.zip", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func TestListAndModPassThroughGoProxySchema(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.invalid/registrygate/fixture/@v/list":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("v1.0.0\nv1.1.0\n"))
		case "/example.invalid/registrygate/fixture/@v/v1.0.0.mod":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("module example.invalid/registrygate/fixture\n\ngo 1.24\n"))
		case "/example.invalid/registrygate/fixture/@v/v1.0.0.info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(goInfoFixture))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	r := chi.NewRouter()
	gomod.NewTestAdapter(gomod.Config{
		UpstreamURL: upstream.URL,
		PolicyEng:   policy.NewEngine(nil),
		Recorder:    history.NewNoopRecorder(),
	}).Mount(r)

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/gomod/example.invalid/registrygate/fixture/@v/list", "v1.0.0\nv1.1.0\n"},
		{"/gomod/example.invalid/registrygate/fixture/@v/v1.0.0.mod", "module example.invalid/registrygate/fixture"},
	} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.ServeHTTP(resp, req)
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", tc.path, resp.Code)
		}
		if !strings.Contains(resp.Body.String(), tc.want) {
			t.Fatalf("%s: response mismatch: %s", tc.path, resp.Body.String())
		}
	}
}

func denyEngine(eco facts.Ecosystem, pkg string) *policy.Engine {
	return policy.NewEngine([]policy.Entry{{
		Match: policy.Match{PackagePatterns: []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}},
		Rule:  rules.NewDenyPatterns(string(eco)+"/deny", []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}),
	}})
}

const goInfoFixture = `{
  "Version": "v1.0.0",
  "Time": "2026-01-02T03:04:05Z",
  "Origin": {
    "VCS": "git",
    "URL": "https://example.invalid/registrygate/fixture.git",
    "Hash": "0123456789abcdef0123456789abcdef01234567",
    "Ref": "refs/tags/v1.0.0"
  }
}`
