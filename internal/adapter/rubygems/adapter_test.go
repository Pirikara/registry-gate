package rubygems_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registory-gate/internal/adapter/rubygems"
	"github.com/pirikara/registory-gate/internal/cache"
	"github.com/pirikara/registory-gate/internal/history"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
)

func makeVersionList(name, version string, ageDays int, yanked bool) rubygems.VersionList {
	return rubygems.VersionList{{
		Number:    version,
		CreatedAt: time.Now().AddDate(0, 0, -ageDays).Format(time.RFC3339),
		Yanked:    yanked,
	}}
}

func buildUpstream(vl rubygems.VersionList) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/versions/rails.json" || r.URL.Path == "/api/v1/versions/newgem.json" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(vl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func buildAdapter(upstreamURL string, eng *policy.Engine) *rubygems.Adapter {
	return rubygems.NewTestAdapter(rubygems.Config{
		UpstreamURL: upstreamURL,
		PolicyEng:   eng,
		Recorder:    history.NewNoopRecorder(),
		Cache:       cache.NoopCache{},
	})
}

func openEng() *policy.Engine {
	return policy.NewEngine(nil)
}

// --- Version list ---

func TestRubyGems_VersionList_OK(t *testing.T) {
	upstream := buildUpstream(makeVersionList("rails", "7.1.0", 30, false))
	defer upstream.Close()

	r := chi.NewRouter()
	buildAdapter(upstream.URL, openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/api/v1/versions/rails.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var vl rubygems.VersionList
	_ = json.NewDecoder(resp.Body).Decode(&vl)
	if len(vl) == 0 {
		t.Error("expected at least one version in response")
	}
}

func TestRubyGems_VersionList_BlockedVersionRemoved(t *testing.T) {
	// 2-day-old gem; cooldown requires 7 days.
	upstream := buildUpstream(makeVersionList("newgem", "0.1.0", 2, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/api/v1/versions/newgem.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var vl rubygems.VersionList
	_ = json.NewDecoder(resp.Body).Decode(&vl)
	for _, v := range vl {
		if v.Number == "0.1.0" {
			t.Error("blocked version should not appear in version list")
		}
	}
}

// --- Gem download ---

func TestRubyGems_GemDownload_Allowed_Redirect(t *testing.T) {
	upstream := buildUpstream(makeVersionList("rails", "7.1.0", 30, false))
	defer upstream.Close()

	r := chi.NewRouter()
	buildAdapter(upstream.URL, openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/gems/rails-7.1.0.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
}

func TestRubyGems_GemDownload_Blocked_403(t *testing.T) {
	upstream := buildUpstream(makeVersionList("newgem", "0.0.1", 1, false))
	// Need to handle the newgem version list URL too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makeVersionList("newgem", "0.0.1", 1, false))
	}))
	defer upstream.Close()
	defer srv.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildAdapter(srv.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gems/newgem-0.0.1.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// --- Trust downgrade (rubygems_mfa_required) ---

// makeVersionDetail returns a minimal /api/v2/.../versions/{ver}.json body.
func makeVersionDetail(name, version, authors string, mfaRequired *bool, ageDays int) []byte {
	created := time.Now().AddDate(0, 0, -ageDays).Format(time.RFC3339)
	meta := map[string]string{}
	if mfaRequired != nil {
		if *mfaRequired {
			meta["rubygems_mfa_required"] = "true"
		} else {
			meta["rubygems_mfa_required"] = "false"
		}
	}
	body := map[string]any{
		"name":               name,
		"number":             version,
		"authors":            authors,
		"version_created_at": created,
		"created_at":         created,
		"metadata":           meta,
	}
	raw, _ := json.Marshal(body)
	return raw
}

// buildVersionedUpstream serves both the versions list and per-version detail
// endpoints, with the MFA flag controllable per version.
func buildVersionedUpstream(name string, versions []rubygems.VersionInfo, mfaByVersion map[string]*bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/versions/"+name+".json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(versions)
			return
		case len(r.URL.Path) > len("/api/v2/rubygems/"+name+"/versions/"):
			// /api/v2/rubygems/{name}/versions/{version}.json
			version := r.URL.Path[len("/api/v2/rubygems/"+name+"/versions/"):]
			version = version[:len(version)-len(".json")]
			mfa := mfaByVersion[version]
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeVersionDetail(name, version, "Author Name", mfa, 30))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestRubyGems_GemDownload_TrustDowngrade_Blocked(t *testing.T) {
	yes := true
	no := false
	versions := []rubygems.VersionInfo{
		// Newest first, matching rubygems API ordering.
		{Number: "2.0.0", CreatedAt: time.Now().AddDate(0, 0, -3).Format(time.RFC3339)},
		{Number: "1.1.0", CreatedAt: time.Now().AddDate(0, 0, -45).Format(time.RFC3339)},
		{Number: "1.0.0", CreatedAt: time.Now().AddDate(0, 0, -60).Format(time.RFC3339)},
	}
	upstream := buildVersionedUpstream("mygem", versions, map[string]*bool{
		"1.0.0": &yes,
		"1.1.0": &yes,
		"2.0.0": &no, // MFA disabled in newer release → downgrade
	})
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade(
			"trust",
			[]rules.TrustDowngradeWatch{rules.WatchPublisherTwoFactor},
			rules.OnUnknownIgnore,
		),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gems/mygem-2.0.0.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for MFA downgrade, got %d", resp.StatusCode)
	}
}

func TestRubyGems_GemDownload_TrustConsistent_Allowed(t *testing.T) {
	yes := true
	versions := []rubygems.VersionInfo{
		{Number: "2.0.0", CreatedAt: time.Now().AddDate(0, 0, -3).Format(time.RFC3339)},
		{Number: "1.1.0", CreatedAt: time.Now().AddDate(0, 0, -45).Format(time.RFC3339)},
		{Number: "1.0.0", CreatedAt: time.Now().AddDate(0, 0, -60).Format(time.RFC3339)},
	}
	upstream := buildVersionedUpstream("mygem", versions, map[string]*bool{
		"1.0.0": &yes,
		"1.1.0": &yes,
		"2.0.0": &yes,
	})
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewTrustDowngrade(
			"trust",
			[]rules.TrustDowngradeWatch{rules.WatchPublisherTwoFactor},
			rules.OnUnknownIgnore,
		),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/gems/mygem-2.0.0.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
}

// --- parseGemFilename ---

func TestParseGemFilename(t *testing.T) {
	cases := []struct {
		input   string
		name    string
		version string
	}{
		{"rails-7.1.0.gem", "rails", "7.1.0"},
		{"my-gem-name-1.2.3.gem", "my-gem-name", "1.2.3"},
		{"nokogiri-1.16.0-x86_64-linux.gem", "nokogiri", "1.16.0-x86_64-linux"},
		{"abc.gem", "abc", ""},
	}
	for _, tc := range cases {
		n, v := rubygems.ParseGemFilenameExported(tc.input)
		if n != tc.name || v != tc.version {
			t.Errorf("parseGemFilename(%q) = (%q, %q); want (%q, %q)",
				tc.input, n, v, tc.name, tc.version)
		}
	}
}

func TestRubyGems_GemDownload_DenyList_Block(t *testing.T) {
	upstream := buildUpstream(makeVersionList("newgem", "1.0.0", 30, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewDeny("deny", []policy.PackageRef{
			{Ecosystem: "rubygems", Name: "newgem"},
		}),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gems/newgem-1.0.0.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 from deny list, got %d", resp.StatusCode)
	}
}

// ブロック時に両方のヘッダーが設定されていること。
func TestRubyGems_GemDownload_Block_HeadersPresent(t *testing.T) {
	upstream := buildUpstream(makeVersionList("newgem", "0.0.1", 1, false))
	defer upstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildAdapter(upstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/gems/newgem-0.0.1.gem")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-RegistoryGate-Block-Reason") == "" {
		t.Error("X-RegistoryGate-Block-Reason header should be set on block")
	}
	if resp.Header.Get("X-RegistoryGate-Block-Detail") == "" {
		t.Error("X-RegistoryGate-Block-Detail header should be set on block")
	}
}
