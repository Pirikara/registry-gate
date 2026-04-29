package pypi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/pypi"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

// upstreamConfig drives the test upstream server: it routes requests by path
// to the appropriate response so /pypi/.../json and /integrity/.../provenance
// behave like real PyPI rather than returning the same blob for every URL.
type upstreamConfig struct {
	jsonAPI     *pypi.JSONAPIResponse
	provenance  map[string]*pypi.PEP740Bundle // key: filename → bundle (404 if missing)
	provHits    map[string]int                // observability: count requests per filename
}

func buildPyPIUpstream(resp *pypi.JSONAPIResponse) *httptest.Server {
	return buildPyPIUpstreamFull(upstreamConfig{jsonAPI: resp})
}

func buildPyPIUpstreamFull(cfg upstreamConfig) *httptest.Server {
	if cfg.provHits == nil {
		cfg.provHits = map[string]int{}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /integrity/{pkg}/{ver}/{filename}/provenance
		if strings.HasPrefix(r.URL.Path, "/integrity/") && strings.HasSuffix(r.URL.Path, "/provenance") {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/integrity/"), "/")
			if len(parts) < 4 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			filename := parts[2]
			cfg.provHits[filename]++
			b, ok := cfg.provenance[filename]
			if !ok || b == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(b)
			return
		}
		// /pypi/{pkg}/json
		if cfg.jsonAPI != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg.jsonAPI)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

func makePyPIResp(name, version string, ageDays int) *pypi.JSONAPIResponse {
	uploadTime := time.Now().AddDate(0, 0, -ageDays).Format(time.RFC3339)
	return &pypi.JSONAPIResponse{
		Info: pypi.PackageInfo{Name: name, Version: version},
		Releases: map[string][]pypi.ReleaseFile{
			version: {
				{
					Filename:      name + "-" + version + "-py3-none-any.whl",
					URL:           "https://files.pythonhosted.org/packages/" + name + "-" + version + ".whl#sha256=abc",
					PackageType:   "bdist_wheel",
					UploadTimeISO: uploadTime,
				},
			},
		},
	}
}

func buildPyPIAdapter(upstreamURL string, eng *policy.Engine) *pypi.Adapter {
	return pypi.NewTestAdapter(pypi.Config{
		UpstreamURL: upstreamURL,
		ProxyBase:   "http://localhost:8080",
		PolicyEng:   eng,
		Recorder:    history.NewNoopRecorder(),
		Cache:       cache.NoopCache{},
	})
}

func openEng() *policy.Engine {
	return policy.NewEngine(nil)
}

// --- JSON API endpoint ---

func TestPyPI_JSONAPI_OK(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("requests", "2.31.0", 30))
	defer upstream.Close()

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/pypi/requests/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var data pypi.JSONAPIResponse
	_ = json.NewDecoder(resp.Body).Decode(&data)
	if data.Info.Name != "requests" {
		t.Errorf("unexpected name: %s", data.Info.Name)
	}
}

func TestPyPI_JSONAPI_BlockedVersionRemoved(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("newpkg", "0.1.0", 2))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/pypi/newpkg/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var data pypi.JSONAPIResponse
	_ = json.NewDecoder(resp.Body).Decode(&data)
	if _, ok := data.Releases["0.1.0"]; ok {
		t.Error("blocked version should be removed from releases map")
	}
}

// --- Package download endpoint ---

func TestPyPI_Package_Allowed_Redirect(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("requests", "2.31.0", 30))
	defer upstream.Close()

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/packages/requests-2.31.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "files.pythonhosted.org") {
		t.Errorf("redirect should go to pythonhosted.org, got: %s", loc)
	}
}

func TestPyPI_Package_Blocked_403(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("newpkg", "0.0.1", 1))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/packages/newpkg-0.0.1-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// --- Trust downgrade (PEP 740) ---

// makeMultiVersionResp builds a JSON API response with multiple versions so
// the adapter has a baseline to compare against.
func makeMultiVersionResp(name string, versions map[string]int) *pypi.JSONAPIResponse {
	releases := map[string][]pypi.ReleaseFile{}
	for ver, ageDays := range versions {
		uploadTime := time.Now().AddDate(0, 0, -ageDays).Format(time.RFC3339)
		releases[ver] = []pypi.ReleaseFile{{
			Filename:      name + "-" + ver + "-py3-none-any.whl",
			URL:           "https://files.pythonhosted.org/packages/" + name + "-" + ver + ".whl#sha256=abc",
			PackageType:   "bdist_wheel",
			UploadTimeISO: uploadTime,
		}}
	}
	return &pypi.JSONAPIResponse{
		Info:     pypi.PackageInfo{Name: name, Version: "1.0.0"},
		Releases: releases,
	}
}

func trustedBundle(repo string) *pypi.PEP740Bundle {
	return &pypi.PEP740Bundle{
		Version: 1,
		AttestationBundles: []pypi.AttestationBundle{{
			Publisher: &pypi.PEP740Publisher{
				Kind:       "GitHub",
				Repository: repo,
				Workflow:   "release.yml",
			},
		}},
	}
}

func TestPyPI_Package_TrustDowngrade_Blocked(t *testing.T) {
	// Baseline (older, trusted): v1.0.0, v1.1.0 — both have provenance.
	// Target (newer, downgraded): v2.0.0 — no provenance (404).
	resp := makeMultiVersionResp("mypkg", map[string]int{
		"1.0.0": 60,
		"1.1.0": 45,
		"2.0.0": 5,
	})
	upstream := buildPyPIUpstreamFull(upstreamConfig{
		jsonAPI: resp,
		provenance: map[string]*pypi.PEP740Bundle{
			"mypkg-1.0.0-py3-none-any.whl": trustedBundle("acme/mypkg"),
			"mypkg-1.1.0-py3-none-any.whl": trustedBundle("acme/mypkg"),
			// 2.0.0 deliberately missing → 404 from PEP 740 endpoint
		},
	})
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade(
			"trust",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownIgnore,
		),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp2, err := http.Get(proxy.URL + "/packages/mypkg-2.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for trust downgrade, got %d", resp2.StatusCode)
	}
}

func TestPyPI_Package_TrustConsistent_Allowed(t *testing.T) {
	// All versions have provenance: no downgrade → allowed.
	resp := makeMultiVersionResp("mypkg", map[string]int{
		"1.0.0": 60,
		"1.1.0": 45,
		"2.0.0": 5,
	})
	upstream := buildPyPIUpstreamFull(upstreamConfig{
		jsonAPI: resp,
		provenance: map[string]*pypi.PEP740Bundle{
			"mypkg-1.0.0-py3-none-any.whl": trustedBundle("acme/mypkg"),
			"mypkg-1.1.0-py3-none-any.whl": trustedBundle("acme/mypkg"),
			"mypkg-2.0.0-py3-none-any.whl": trustedBundle("acme/mypkg"),
		},
	})
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade(
			"trust",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownIgnore,
		),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp2, err := client.Get(proxy.URL + "/packages/mypkg-2.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (allowed), got %d", resp2.StatusCode)
	}
}

func TestPyPI_Package_SDist_Blocked_403(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("mypkg", "1.0.0", 1))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/packages/mypkg-1.0.0.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for sdist with cooldown policy, got %d", resp.StatusCode)
	}
}

func TestPyPI_Package_DenyList_Block(t *testing.T) {
	// PyPI wheel filenames use underscores for package names (PEP 427).
	// "bannedpkg" has no hyphens to avoid the ambiguity between name separators
	// and version separators when parsing the wheel filename.
	upstream := buildPyPIUpstream(makePyPIResp("bannedpkg", "1.0.0", 30))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewDeny("deny", []policy.PackageRef{
			{Ecosystem: "pypi", Name: "bannedpkg"},
		}),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/packages/bannedpkg-1.0.0-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from deny list, got %d", resp.StatusCode)
	}
}

// ブロック時に両方のヘッダーが設定されていること。
func TestPyPI_Package_Block_HeadersPresent(t *testing.T) {
	upstream := buildPyPIUpstream(makePyPIResp("newpkg", "0.0.1", 1))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildPyPIAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/packages/newpkg-0.0.1-py3-none-any.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-RegistryGate-Block-Reason") == "" {
		t.Error("X-RegistryGate-Block-Reason header should be set on block")
	}
	if resp.Header.Get("X-RegistryGate-Block-Detail") == "" {
		t.Error("X-RegistryGate-Block-Detail header should be set on block")
	}
}
