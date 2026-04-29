package homebrew_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registory-gate/internal/adapter/homebrew"
	"github.com/pirikara/registory-gate/internal/cache"
	"github.com/pirikara/registory-gate/internal/history"
	"github.com/pirikara/registory-gate/internal/policy"
	"github.com/pirikara/registory-gate/internal/policy/rules"
)

func buildFormulaServer(formulaName, tap string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(homebrew.FormulaInfo{
			Name: formulaName,
			Tap:  tap,
		})
	}))
}

func buildBottleAdapter(formulaURL, upstreamURL string, eng *policy.Engine) *homebrew.Adapter {
	return homebrew.NewTestAdapter(homebrew.Config{
		UpstreamURL:   upstreamURL,
		FormulaAPIURL: formulaURL,
		PolicyEng:     eng,
		Recorder:      history.NewNoopRecorder(),
		Cache:         cache.NoopCache{},
	})
}

func openEng() *policy.Engine {
	return policy.NewEngine(nil)
}

// --- ParseBottleFilename ---

func TestParseBottleFilename(t *testing.T) {
	cases := []struct {
		input   string
		formula string
		version string
	}{
		{"git--2.42.0.arm64_sonoma.bottle.tar.gz", "git", "2.42.0"},
		{"node--21.0.0.arm64_sonoma.bottle.1.tar.gz", "node", "21.0.0"},
		{"libpng--1.6.40.arm64_sonoma.bottle.tar.gz", "libpng", "1.6.40"},
		{"python@3.11--3.11.6.arm64_sonoma.bottle.tar.gz", "python@3.11", "3.11.6"},
	}
	for _, tc := range cases {
		f, v := homebrew.ParseBottleFilename(tc.input)
		if f != tc.formula || v != tc.version {
			t.Errorf("ParseBottleFilename(%q) = (%q,%q); want (%q,%q)",
				tc.input, f, v, tc.formula, tc.version)
		}
	}
}

// --- Bottle endpoint ---

func TestHomebrew_Bottle_Allowed_Redirect(t *testing.T) {
	formulaSrv := buildFormulaServer("git", "homebrew/core")
	bottleUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer formulaSrv.Close()
	defer bottleUpstream.Close()

	r := chi.NewRouter()
	buildBottleAdapter(formulaSrv.URL, bottleUpstream.URL, openEng()).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(proxy.URL + "/bottles/git--2.42.0.arm64_sonoma.bottle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
}

func TestHomebrew_Bottle_Blocked_403(t *testing.T) {
	formulaSrv := buildFormulaServer("newformula", "homebrew/core")
	bottleUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer formulaSrv.Close()
	defer bottleUpstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewDeny("deny", []policy.PackageRef{{
			Ecosystem: "homebrew",
			Name:      "newformula",
		}}),
	}})

	r := chi.NewRouter()
	buildBottleAdapter(formulaSrv.URL, bottleUpstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/bottles/newformula--1.0.0.arm64_sonoma.bottle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// Homebrew アダプターは PublishedAt を取得しないため、cooldown は常に
// "published_at unknown" としてブロックする。
func TestHomebrew_Bottle_Cooldown_Block(t *testing.T) {
	formulaSrv := buildFormulaServer("git", "homebrew/core")
	bottleUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer formulaSrv.Close()
	defer bottleUpstream.Close()

	eng := policy.NewEngine([]policy.Entry{{
		Rule: rules.NewCooldown("cd", 7),
	}})

	r := chi.NewRouter()
	buildBottleAdapter(formulaSrv.URL, bottleUpstream.URL, eng).Mount(r)
	proxy := httptest.NewServer(r)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/bottles/git--2.42.0.arm64_sonoma.bottle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 (published_at unknown → cooldown blocks), got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-RegistoryGate-Block-Reason") == "" {
		t.Error("X-RegistoryGate-Block-Reason header should be set on block")
	}
	if resp.Header.Get("X-RegistoryGate-Block-Detail") == "" {
		t.Error("X-RegistoryGate-Block-Detail header should be set on block")
	}
}
