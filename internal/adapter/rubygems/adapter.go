package rubygems

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registory-gate/internal/adapter/principal"
	"github.com/pirikara/registory-gate/internal/cache"
	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/history"
	"github.com/pirikara/registory-gate/internal/policy"
)

const (
	versionsCacheTTL      = 2 * time.Minute
	versionDetailCacheTTL = 24 * time.Hour // per-version metadata is immutable once published
	baselineLimit         = 5
)

// Adapter proxies RubyGems registry requests in mirror mode.
//
// Routes:
//   GET /api/v1/versions/{name}.json  → version list with blocked versions removed
//   GET /gems/{file}                  → policy check + 302 redirect
//   GET /*                            → transparent proxy
type Adapter struct {
	upstreamURL string
	policyEng   *policy.Engine
	recorder    history.Recorder
	cache       cache.Cache
	httpClient  *http.Client
	logger      *slog.Logger
}

type Config struct {
	UpstreamURL string
	PolicyEng   *policy.Engine
	Recorder    history.Recorder
	Cache       cache.Cache
	HTTPClient  *http.Client
	Logger      *slog.Logger
}

func NewAdapter(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		upstreamURL: strings.TrimRight(cfg.UpstreamURL, "/"),
		policyEng:   cfg.PolicyEng,
		recorder:    cfg.Recorder,
		cache:       cfg.Cache,
		httpClient:  cfg.HTTPClient,
		logger:      cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

func (a *Adapter) Mount(r chi.Router) {
	r.Get("/api/v1/versions/{name}.json", a.handleVersionList)
	r.Get("/gems/{gemfile}", a.handleGemDownload)
	r.HandleFunc("/api/v1/*", a.handleTransparentProxy)
	r.HandleFunc("/api/v2/*", a.handleTransparentProxy)
	r.HandleFunc("/quick/*", a.handleTransparentProxy)
	r.HandleFunc("/specs.4.8.gz", a.handleTransparentProxy)
	r.HandleFunc("/latest_specs.4.8.gz", a.handleTransparentProxy)
	r.HandleFunc("/prerelease_specs.4.8.gz", a.handleTransparentProxy)
	// Compact Index API (RFC: https://guides.rubygems.org/rubygems-org-compact-index-api/)
	// Passing these through transparently is safe — policy is enforced at /gems/{file}.
	r.HandleFunc("/versions", a.handleTransparentProxy)
	r.HandleFunc("/info/*", a.handleTransparentProxy)
	r.HandleFunc("/names", a.handleTransparentProxy)
}

func (a *Adapter) handleVersionList(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	raw, err := a.fetchVersionList(ctx, name)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch version list", "gem", name, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	versions, err := ParseVersionList(raw)
	if err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	var allowed VersionList
	for _, v := range versions {
		pf := v.ToPackageFacts(name)
		result, err := a.policyEng.Evaluate(ctx, *pf)
		if err != nil || result.Decision != policy.DecisionBlock {
			allowed = append(allowed, v)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(allowed)
}

func (a *Adapter) handleGemDownload(w http.ResponseWriter, r *http.Request) {
	gemfile := chi.URLParam(r, "gemfile")
	ctx := r.Context()

	name, version := parseGemFilename(gemfile)

	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemRubyGems,
		Name:      name,
		Version:   version,
	}

	// Try to enrich with per-version detail (gives us the trust signals).
	// Fall back to the version list if the detail endpoint is unavailable.
	if vd, err := a.fetchVersionDetail(ctx, name, version); err == nil && vd != nil {
		pf = vd.ToPackageFacts()
	} else if raw, err := a.fetchVersionList(ctx, name); err == nil {
		if versions, err := ParseVersionList(raw); err == nil {
			for _, v := range versions {
				if v.Number == version {
					pf = v.ToPackageFacts(name)
					break
				}
			}
		}
	}

	baseline := a.buildBaseline(ctx, name, version)

	result, err := a.policyEng.Evaluate(ctx, *pf, policy.WithBaseline(baseline))
	if err != nil {
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	outcome := history.OutcomeAllowed
	blockReason := ""
	if result.Decision == policy.DecisionBlock {
		outcome = history.OutcomeBlocked
		blockReason = result.BlockReason()
	}

	label := principal.Label(r)
	ua := r.Header.Get("User-Agent")
	go func() {
		_ = a.recorder.Record(context.Background(), history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemRubyGems,
			PackageName:    name,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistoryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistoryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}

	http.Redirect(w, r, a.upstreamURL+"/gems/"+gemfile, http.StatusFound)
}

func (a *Adapter) handleTransparentProxy(w http.ResponseWriter, r *http.Request) {
	upstream := a.upstreamURL + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	for k, vals := range r.Header {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (a *Adapter) fetchVersionList(ctx context.Context, name string) ([]byte, error) {
	key := "rubygems:versions:" + name
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, key); err == nil {
			return cached, nil
		}
	}
	url := fmt.Sprintf("%s/api/v1/versions/%s.json", a.upstreamURL, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, key, body, versionsCacheTTL)
	}
	return body, nil
}

// fetchVersionDetail hits /api/v2/rubygems/{name}/versions/{version}.json,
// which carries per-version metadata including rubygems_mfa_required.
// Caches successful fetches with a long TTL (the response is immutable).
func (a *Adapter) fetchVersionDetail(ctx context.Context, name, version string) (*VersionDetail, error) {
	key := fmt.Sprintf("rubygems:vdetail:%s/%s", name, version)
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, key); err == nil {
			return ParseVersionDetail(cached)
		}
	}
	url := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", a.upstreamURL, name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, key, body, versionDetailCacheTTL)
	}
	return ParseVersionDetail(body)
}

// buildBaseline picks the most-recent N other versions from the version list
// and fetches per-version detail for each so trust_downgrade has trust facts
// to compare against.
func (a *Adapter) buildBaseline(ctx context.Context, name, target string) []facts.PackageFacts {
	raw, err := a.fetchVersionList(ctx, name)
	if err != nil {
		return nil
	}
	versions, err := ParseVersionList(raw)
	if err != nil {
		return nil
	}
	// versions arrive newest-first from the API; filter target out and cap.
	var picked []VersionInfo
	for _, v := range versions {
		if v.Number == target || v.Yanked {
			continue
		}
		picked = append(picked, v)
		if len(picked) >= baselineLimit {
			break
		}
	}
	out := make([]facts.PackageFacts, 0, len(picked))
	for _, v := range picked {
		if vd, err := a.fetchVersionDetail(ctx, name, v.Number); err == nil && vd != nil {
			out = append(out, *vd.ToPackageFacts())
		}
	}
	return out
}

// ParseGemFilenameExported is the exported version of parseGemFilename for tests.
var ParseGemFilenameExported = parseGemFilename

// parseGemFilename extracts name and version from e.g. "rails-7.1.0.gem"
// Version starts with a digit; finds the last "-{digit}" boundary.
func parseGemFilename(filename string) (name, version string) {
	base := strings.TrimSuffix(filename, ".gem")
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '-' && i+1 < len(base) && base[i+1] >= '0' && base[i+1] <= '9' {
			return base[:i], base[i+1:]
		}
	}
	return base, ""
}
