package composer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/composer"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

func buildComposerUpstream(t *testing.T, versionAgeDays int) *httptest.Server {
	t.Helper()
	created := time.Now().AddDate(0, 0, -versionAgeDays).Format(time.RFC3339)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/packages.json":
			_, _ = w.Write([]byte(`{
				"metadata-url": "/p2/%package%.json",
				"notify-batch": "https://packagist.org/downloads/",
				"providers-url": "/p/%package%$%hash%.json",
				"provider-includes": {"p/provider.json": {"sha256": "abc"}}
			}`))
		case "/p2/acme/demo.json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"minified": "composer/2.0",
				"packages": map[string]any{
					"acme/demo": []any{
						map[string]any{
							"name":    "acme/demo",
							"version": "1.0.0",
							"time":    created,
							"dist": map[string]any{
								"type": "zip",
								"url":  "https://api.github.com/repos/acme/demo/zipball/1.0.0",
							},
							"source": map[string]any{
								"type": "git",
								"url":  "https://github.com/acme/demo.git",
							},
						},
						map[string]any{
							"version": "0.9.0",
							"time":    time.Now().AddDate(0, 0, -90).Format(time.RFC3339),
							"dist": map[string]any{
								"type": "zip",
								"url":  "https://api.github.com/repos/acme/demo/zipball/0.9.0",
							},
							"source": map[string]any{
								"type": "git",
								"url":  "https://github.com/acme/demo.git",
							},
						},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func buildAdapter(upstreamURL, proxyBase string, eng *policy.Engine) *composer.Adapter {
	return composer.NewTestAdapter(composer.Config{
		UpstreamURL: upstreamURL,
		ProxyBase:   proxyBase,
		PolicyEng:   eng,
		Recorder:    history.NewNoopRecorder(),
		Cache:       cache.NoopCache{},
	})
}

func openEng() *policy.Engine {
	return policy.NewEngine(nil)
}

func TestComposer_PackagesJSON_RewritesToP2Only(t *testing.T) {
	upstream := buildComposerUpstream(t, 30)
	defer upstream.Close()

	r := chi.NewRouter()
	buildAdapter(upstream.URL, "https://proxy.example.com", openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/packages.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var root map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&root); err != nil {
		t.Fatal(err)
	}
	if root["metadata-url"] != "/p2/%package%.json" {
		t.Fatalf("metadata-url = %v", root["metadata-url"])
	}
	if _, ok := root["providers-url"]; ok {
		t.Fatal("providers-url should be removed so Composer uses p2 metadata")
	}
	if _, ok := root["notify-batch"]; ok {
		t.Fatal("notify-batch should be removed so Composer does not call Packagist directly")
	}
}

func TestComposer_P2_BlockedVersionRemovedAndDistRewritten(t *testing.T) {
	upstream := buildComposerUpstream(t, 1)
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, "https://proxy.example.com", eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/p2/acme/demo.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var body struct {
		Packages map[string][]map[string]any `json:"packages"`
		Minified string                      `json:"minified,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	versions := body.Packages["acme/demo"]
	if len(versions) != 1 {
		t.Fatalf("expected one allowed version, got %d", len(versions))
	}
	if versions[0]["version"] != "0.9.0" {
		t.Fatalf("expected 0.9.0 to remain, got %v", versions[0]["version"])
	}
	dist := versions[0]["dist"].(map[string]any)
	if url, _ := dist["url"].(string); !strings.HasPrefix(url, "https://proxy.example.com/composer/dist/") {
		t.Fatalf("dist url was not rewritten through proxy: %s", url)
	}
	if _, ok := versions[0]["source"]; ok {
		t.Fatal("source should be removed to prevent Composer fallback around dist policy")
	}
	if body.Minified != "" {
		t.Fatalf("filtered response should be emitted unminified, got %q", body.Minified)
	}
}

func TestComposer_Dist_Allowed_Redirect(t *testing.T) {
	upstream := buildComposerUpstream(t, 30)
	defer upstream.Close()

	r := chi.NewRouter()
	adp := buildAdapter(upstream.URL, "https://proxy.example.com", openEng())
	adp.Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	distURL := composer.BuildDistProxyURL(proxy.URL, "acme/demo", "1.0.0", "https://api.github.com/repos/acme/demo/zipball/1.0.0")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(distURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://api.github.com/repos/acme/demo/zipball/1.0.0" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

func TestComposer_Dist_RejectsURLNotInUpstreamMetadata(t *testing.T) {
	upstream := buildComposerUpstream(t, 30)
	defer upstream.Close()

	r := chi.NewRouter()
	adp := buildAdapter(upstream.URL, "https://proxy.example.com", openEng())
	adp.Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	distURL := composer.BuildDistProxyURL(proxy.URL, "acme/demo", "1.0.0", "https://evil.example/phish")
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(distURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}
}

func TestComposer_Dist_Blocked_403(t *testing.T) {
	upstream := buildComposerUpstream(t, 1)
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, "https://proxy.example.com", eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	distURL := composer.BuildDistProxyURL(proxy.URL, "acme/demo", "1.0.0", "https://api.github.com/repos/acme/demo/zipball/1.0.0")
	resp, err := http.Get(distURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}
