package cargo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/cargo"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func TestConfigRewritesDownloadTemplate(t *testing.T) {
	upstream := newCargoIndex()
	defer upstream.Close()

	r := chi.NewRouter()
	cargo.NewTestAdapter(cargo.Config{
		IndexURL:  upstream.URL,
		APIURL:    upstream.URL,
		ProxyBase: "https://proxy.example.com",
		PolicyEng: denyEngine(facts.EcosystemCargo, "demo"),
		Recorder:  history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cargo/index/config.json", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	var cfg map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode cargo config: %v", err)
	}
	if cfg["dl"] != "https://proxy.example.com/cargo/api/v1/crates/{crate}/{version}/download" {
		t.Fatalf("config did not rewrite dl: %s", resp.Body.String())
	}
	if cfg["api"] != "https://proxy.example.com/cargo/api" {
		t.Fatalf("config did not rewrite api: %s", resp.Body.String())
	}
	if cfg["auth-required"] != false {
		t.Fatalf("config did not preserve auth-required: %s", resp.Body.String())
	}
}

func TestSparseIndexPassesThroughSchema(t *testing.T) {
	upstream := newCargoIndex()
	defer upstream.Close()

	r := chi.NewRouter()
	cargo.NewTestAdapter(cargo.Config{
		IndexURL:  upstream.URL,
		APIURL:    upstream.URL,
		ProxyBase: "https://proxy.example.com",
		PolicyEng: policy.NewEngine(nil),
		Recorder:  history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cargo/index/re/gi/registry_gate_fixture_pkg", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), `"cksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`) ||
		!strings.Contains(resp.Body.String(), `"rust_version":"1.74"`) {
		t.Fatalf("index response does not look like sparse registry JSON lines: %s", resp.Body.String())
	}
}

func TestDownloadBlockedByDenyPolicy(t *testing.T) {
	upstream := newCargoIndex()
	defer upstream.Close()

	r := chi.NewRouter()
	cargo.NewTestAdapter(cargo.Config{
		IndexURL:  upstream.URL,
		APIURL:    upstream.URL,
		ProxyBase: "https://proxy.example.com",
		PolicyEng: denyEngine(facts.EcosystemCargo, "registry_gate_fixture_pkg"),
		Recorder:  history.NewNoopRecorder(),
	}).Mount(r)

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/cargo/api/v1/crates/registry_gate_fixture_pkg/1.0.0/download", nil)
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.Code)
	}
}

func newCargoIndex() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cargoConfigFixture))
		case "/re/gi/registry_gate_fixture_pkg":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(cargoIndexFixture))
		default:
			http.NotFound(w, r)
		}
	}))
}

func denyEngine(eco facts.Ecosystem, pkg string) *policy.Engine {
	return policy.NewEngine([]policy.Entry{{
		Match: policy.Match{PackagePatterns: []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}},
		Rule:  rules.NewDenyPatterns(string(eco)+"/deny", []policy.PackagePattern{{Ecosystem: eco, Pattern: pkg}}),
	}})
}

const cargoConfigFixture = `{
  "dl": "https://static.example.invalid/crates",
  "api": "https://crates.example.invalid",
  "auth-required": false
}`

const cargoIndexFixture = `{"name":"registry_gate_fixture_pkg","vers":"1.0.0","deps":[{"name":"registry_gate_fixture_dep","req":"^1.0","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal","registry":null,"package":null}],"cksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","features":{"default":["std"],"std":[]},"yanked":false,"links":null,"rust_version":"1.74","pubtime":"2026-01-02T03:04:05Z"}
`
