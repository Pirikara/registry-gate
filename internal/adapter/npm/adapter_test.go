package npm_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	npmadapter "github.com/pirikara/registry-gate/internal/adapter/npm"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
	"github.com/pirikara/registry-gate/internal/policy/rules"
)

var _ context.Context // keep context import used elsewhere

// noopRecorder drops all records; avoids DB dependency in unit tests.
type noopRecorder struct{}

func (noopRecorder) Record(_ context.Context, _ history.Record) error { return nil }

// stubRecorder captures recorded history for assertion.
type stubRecorder struct {
	records []history.Record
}

func (s *stubRecorder) Record(_ context.Context, rec history.Record) error {
	s.records = append(s.records, rec)
	return nil
}

// testRecorderAdapter wraps the stub to satisfy *history.Recorder shape
// via an interface. We define a local RecorderIface to decouple.
type recorderIface interface {
	Record(context.Context, history.Record) error
}

// We need to inject the recorder. Since history.Recorder is a concrete type,
// we create a thin wrapper that delegates.
type recorderWrapper struct{ r recorderIface }

func (rw *recorderWrapper) Record(ctx context.Context, rec history.Record) error {
	return rw.r.Record(ctx, rec)
}

// buildUpstream creates a test HTTP server that returns fixed npm metadata.
func buildUpstream(meta *npmadapter.RegistryMetadata) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
}

// buildDownloadsAPI creates a mock npm downloads API server that returns a
// fixed download count. The real API lives at api.npmjs.org; tests must point
// the adapter at this server via DownloadsAPIBase to avoid real network calls.
func buildDownloadsAPI(downloads int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"downloads": downloads,
			"package":   "test-pkg",
		})
	}))
}

// buildMeta creates a minimal RegistryMetadata with the given age.
func buildMeta(name, version string, ageDays int, withProvenance bool) *npmadapter.RegistryMetadata {
	var att *npmadapter.Attestations
	if withProvenance {
		att = &npmadapter.Attestations{
			Provenance: &npmadapter.ProvenanceDetail{
				BuilderID:  "https://github.com/actions/runner",
				SourceRepo: "github.com/example/pkg",
			},
		}
	}
	publishedAt := time.Now().AddDate(0, 0, -ageDays).Format(time.RFC3339)
	return &npmadapter.RegistryMetadata{
		Name:     name,
		DistTags: map[string]string{"latest": version},
		Time:     map[string]string{version: publishedAt, "modified": publishedAt},
		Versions: map[string]*npmadapter.VersionMeta{
			version: {
				Name:    name,
				Version: version,
				Dist: npmadapter.DistInfo{
					Tarball:   "https://registry.npmjs.org/" + name + "/-/" + name + "-" + version + ".tgz",
					Integrity: "sha512-test",
				},
				NPMUser:      &npmadapter.NPMUser{Name: "author"},
				Attestations: att,
			},
		},
	}
}

func setupAdapter(eng *policy.Engine) (*httptest.Server, *httptest.Server) {
	upstream := buildUpstream(buildMeta("lodash", "4.17.21", 30, false))
	r := chi.NewRouter()
	buildTestAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	return upstream, proxy
}

// buildTestAdapter builds an Adapter with a noop recorder and noop cache.
// downloadsURL sets DownloadsAPIBase; pass "" to use a no-op stub that returns
// immediately (avoids real api.npmjs.org calls in tests).
func buildTestAdapter(upstreamURL string, eng *policy.Engine, downloadsURL ...string) *npmadapter.Adapter {
	dlBase := ""
	if len(downloadsURL) > 0 && downloadsURL[0] != "" {
		dlBase = downloadsURL[0]
	} else {
		// Stub server that always returns 0 downloads — fast and deterministic.
		stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"downloads":0}`))
		}))
		// The stub leaks but httptest servers are tiny; acceptable for tests.
		dlBase = stub.URL
	}
	return npmadapter.NewTestAdapter(npmadapter.Config{
		UpstreamURL:      upstreamURL,
		ProxyBase:        "http://localhost:8080",
		DownloadsAPIBase: dlBase,
		PolicyEng:        eng,
		Recorder:         history.NewNoopRecorder(),
		Cache:            cache.NoopCache{},
	})
}

func openPolicyEng() *policy.Engine {
	return policy.NewEngine(nil)
}

func cooldownEng(minDays float64) *policy.Engine {
	return policy.NewEngine([]policy.Entry{
		{Rule: rules.NewCooldown("cd", minDays)},
	})
}

// --- Metadata endpoint ---

func TestAdapter_Metadata_OK(t *testing.T) {
	upstream, proxy := setupAdapter(openPolicyEng())
	defer upstream.Close()
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/lodash")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var meta npmadapter.RegistryMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta.Name != "lodash" {
		t.Errorf("expected name=lodash, got %s", meta.Name)
	}
	v := meta.Versions["4.17.21"]
	if v == nil {
		t.Fatal("expected version 4.17.21 in response")
	}
	// Tarball URL must be rewritten to proxy base.
	if !strings.HasPrefix(v.Dist.Tarball, "http://localhost:8080") {
		t.Errorf("tarball URL not rewritten: %s", v.Dist.Tarball)
	}
}

func TestAdapter_Metadata_BlockedVersionStillPresent(t *testing.T) {
	// Policy enforcement is at tarball time, not metadata time.
	// Blocked versions must still appear in metadata so npm can reach the
	// tarball endpoint and receive a clear 403 with the block reason.
	r := chi.NewRouter()
	upstream := buildUpstream(buildMeta("pkg", "1.0.0", 30, false))
	defer upstream.Close()

	adp := npmadapter.NewTestAdapter(npmadapter.Config{
		UpstreamURL: upstream.URL,
		ProxyBase:   "http://localhost:8080",
		PolicyEng:   cooldownEng(90),
		Recorder:    history.NewNoopRecorder(),
		Cache:       cache.NoopCache{},
	})
	adp.Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/pkg")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for metadata, got %d", resp.StatusCode)
	}

	var meta npmadapter.RegistryMetadata
	_ = json.NewDecoder(resp.Body).Decode(&meta)
	if _, ok := meta.Versions["1.0.0"]; !ok {
		t.Error("blocked version must remain in metadata — enforcement happens at tarball download")
	}
}

// --- Tarball endpoint ---

func TestAdapter_Tarball_Allowed_Redirect(t *testing.T) {
	r := chi.NewRouter()
	upstream := buildUpstream(buildMeta("lodash", "4.17.21", 30, false))
	defer upstream.Close()

	buildTestAdapter(upstream.URL, openPolicyEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	// Disable redirect following to check the 302 response directly.
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/lodash/-/lodash-4.17.21.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "lodash-4.17.21.tgz") {
		t.Errorf("redirect location doesn't look right: %s", loc)
	}
}

func TestAdapter_Tarball_Blocked_403(t *testing.T) {
	r := chi.NewRouter()
	// Package is only 1 day old, cooldown requires 7 days.
	upstream := buildUpstream(buildMeta("newpkg", "0.0.1", 1, false))
	defer upstream.Close()

	buildTestAdapter(upstream.URL, cooldownEng(7)).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/newpkg/-/newpkg-0.0.1.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-RegistryGate-Block-Reason") == "" {
		t.Error("expected X-RegistryGate-Block-Reason header")
	}
}

func TestAdapter_Tarball_DenyList_Block(t *testing.T) {
	r := chi.NewRouter()
	upstream := buildUpstream(buildMeta("banned-pkg", "1.0.0", 30, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewDeny("deny", []policy.PackageRef{
			{Ecosystem: "npm", Name: "banned-pkg"},
		}),
	}})
	adp := buildTestAdapter(upstream.URL, eng)
	adp.Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/banned-pkg/-/banned-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from deny list, got %d", resp.StatusCode)
	}
}

// ブロック時に両方のヘッダーが設定されていること。
func TestAdapter_Tarball_Block_HeadersPresent(t *testing.T) {
	r := chi.NewRouter()
	upstream := buildUpstream(buildMeta("newpkg", "0.0.1", 1, false))
	defer upstream.Close()

	adp := buildTestAdapter(upstream.URL, cooldownEng(7))
	adp.Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/newpkg/-/newpkg-0.0.1.tgz")
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

// --- trust_downgrade + tarball ---

// Build metadata with two versions: an older one with provenance (baseline),
// and a newer target without provenance (should be blocked).
func buildMultiVersionMeta() *npmadapter.RegistryMetadata {
	older := time.Now().AddDate(0, 0, -60).Format(time.RFC3339)
	newer := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	return &npmadapter.RegistryMetadata{
		Name: "mypkg",
		Time: map[string]string{
			"1.0.0": older,
			"2.0.0": newer,
		},
		Versions: map[string]*npmadapter.VersionMeta{
			"1.0.0": {
				Name: "mypkg", Version: "1.0.0",
				Dist: npmadapter.DistInfo{
					Tarball: "https://registry.npmjs.org/mypkg/-/mypkg-1.0.0.tgz",
				},
				NPMUser: &npmadapter.NPMUser{Name: "author"},
				Attestations: &npmadapter.Attestations{
					Provenance: &npmadapter.ProvenanceDetail{
						BuilderID:  "https://github.com/actions/runner",
						SourceRepo: "github.com/example/mypkg",
					},
				},
			},
			"2.0.0": {
				Name: "mypkg", Version: "2.0.0",
				Dist: npmadapter.DistInfo{
					Tarball: "https://registry.npmjs.org/mypkg/-/mypkg-2.0.0.tgz",
				},
				NPMUser: &npmadapter.NPMUser{Name: "author"},
				// No Attestations → provenance lost from baseline.
			},
		},
	}
}

func TestAdapter_Tarball_TrustDowngrade_Block(t *testing.T) {
	// Adapter computes inline baseline from metadata.
	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade("td",
			[]rules.TrustDowngradeWatch{rules.WatchProvenancePresent},
			rules.OnUnknownWarn,
		),
	}})

	upstream := buildUpstream(buildMultiVersionMeta())
	defer upstream.Close()

	r := chi.NewRouter()
	buildTestAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/mypkg/-/mypkg-2.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for trust downgrade (provenance lost vs baseline), got %d", resp.StatusCode)
	}
}

// --- min_downloads + npm downloads API ---

func TestAdapter_Tarball_MinDownloads_Block(t *testing.T) {
	dlSrv := buildDownloadsAPI(42) // 42 < 1000 threshold → block
	defer dlSrv.Close()

	upstream := buildUpstream(buildMeta("obscure-pkg", "1.0.0", 30, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewMinDownloads("min-dl", 1000),
	}})

	r := chi.NewRouter()
	buildTestAdapter(upstream.URL, eng, dlSrv.URL).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/obscure-pkg/-/obscure-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 (42 downloads < 1000 threshold), got %d", resp.StatusCode)
	}
}

func TestAdapter_Tarball_MinDownloads_Allow(t *testing.T) {
	dlSrv := buildDownloadsAPI(50000) // 50000 >= 1000 threshold → allow
	defer dlSrv.Close()

	upstream := buildUpstream(buildMeta("popular-pkg", "1.0.0", 30, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewMinDownloads("min-dl", 1000),
	}})

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	r := chi.NewRouter()
	buildTestAdapter(upstream.URL, eng, dlSrv.URL).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := client.Get(proxy.URL + "/popular-pkg/-/popular-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (50000 downloads >= 1000 threshold), got %d", resp.StatusCode)
	}
}
