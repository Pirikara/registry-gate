package npm

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
	metaCacheTTL       = 60 * time.Second
	baselineWindowDays = 90
	baselineLimit      = 10
)

// Adapter handles npm registry proxy requests.
type Adapter struct {
	upstreamURL string
	proxyBase   string
	policyEng   *policy.Engine
	recorder    history.Recorder
	cache       cache.Cache
	httpClient  *http.Client
	logger      *slog.Logger
}

// Config contains all dependencies needed to construct the Adapter.
type Config struct {
	UpstreamURL string
	ProxyBase   string
	PolicyEng   *policy.Engine
	Recorder    history.Recorder
	Cache       cache.Cache
	HTTPClient  *http.Client
	Logger      *slog.Logger
}

// NewTestAdapter is an alias for NewAdapter; provided for clarity in tests.
var NewTestAdapter = NewAdapter

func NewAdapter(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		upstreamURL: strings.TrimRight(cfg.UpstreamURL, "/"),
		proxyBase:   strings.TrimRight(cfg.ProxyBase, "/"),
		policyEng:   cfg.PolicyEng,
		recorder:    cfg.Recorder,
		cache:       cfg.Cache,
		httpClient:  cfg.HTTPClient,
		logger:      cfg.Logger,
	}
}

// Mount registers the adapter routes on the given router.
// Routes:
//
//	GET /{pkg}           → package metadata (scoped: /@scope/{pkg})
//	GET /{pkg}/-/{file}  → tarball redirect
func (a *Adapter) Mount(r chi.Router) {
	r.Get("/{pkg}", a.handleMetadata)
	r.Get("/{scope}/{pkg}", a.handleScopedMetadata)
	r.Get("/{pkg}/-/{file}", a.handleTarball)
	r.Get("/{scope}/{pkg}/-/{file}", a.handleScopedTarball)
}

// handleMetadata proxies and filters the npm package metadata.
func (a *Adapter) handleMetadata(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "pkg")
	a.serveMetadata(w, r, pkg)
}

func (a *Adapter) handleScopedMetadata(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	pkg := chi.URLParam(r, "pkg")
	a.serveMetadata(w, r, scope+"/"+pkg)
}

func (a *Adapter) handleTarball(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "pkg")
	file := chi.URLParam(r, "file")
	a.serveTarball(w, r, pkg, file)
}

func (a *Adapter) handleScopedTarball(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	pkg := chi.URLParam(r, "pkg")
	file := chi.URLParam(r, "file")
	a.serveTarball(w, r, scope+"/"+pkg, file)
}

// serveMetadata fetches metadata and rewrites tarball URLs to route through
// this proxy. Policy enforcement happens at tarball download time (serveTarball),
// not here — so blocked versions still appear in the version list but return
// 403 when actually downloaded. This ensures:
//   - Users see a clear "403 Forbidden: <reason>" instead of "no matching version"
//   - Every blocked download attempt is recorded in the audit log
func (a *Adapter) serveMetadata(w http.ResponseWriter, r *http.Request, pkg string) {
	ctx := r.Context()

	raw, err := a.fetchMetadata(ctx, pkg)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch upstream metadata", "pkg", pkg, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	meta, err := ParseMetadata(raw)
	if err != nil {
		a.logger.ErrorContext(ctx, "parse upstream metadata", "pkg", pkg, "err", err)
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	meta.RewriteTarballURLs(a.proxyBase)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meta); err != nil {
		a.logger.ErrorContext(ctx, "encode metadata response", "err", err)
	}
}

// serveTarball evaluates policy for the specific version and either redirects
// to the upstream tarball or returns 403.
func (a *Adapter) serveTarball(w http.ResponseWriter, r *http.Request, pkg, file string) {
	ctx := r.Context()

	// Extract version from file name: {pkg}-{version}.tgz
	version := extractVersion(pkg, file)

	// Fetch metadata to build facts (we need publish time and trust signals).
	raw, err := a.fetchMetadata(ctx, pkg)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch metadata for tarball check", "pkg", pkg, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	meta, err := ParseMetadata(raw)
	if err != nil {
		a.logger.ErrorContext(ctx, "parse upstream metadata", "pkg", pkg, "err", err)
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	var pf *facts.PackageFacts
	if version != "" {
		pf, _ = meta.ToPackageFacts(version)
	}
	if pf == nil {
		pf = &facts.PackageFacts{
			Ecosystem: facts.EcosystemNPM,
			Name:      pkg,
			Version:   version,
		}
	}

	baseline := meta.BaselineFromMetadata(version, baselineWindowDays, baselineLimit)
	result, err := a.policyEng.Evaluate(ctx, *pf, policy.WithBaseline(baseline))
	if err != nil {
		a.logger.ErrorContext(ctx, "policy eval for tarball", "pkg", pkg, "version", version, "err", err)
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	outcome := history.OutcomeAllowed
	blockReason := ""
	if result.Decision == policy.DecisionBlock {
		outcome = history.OutcomeBlocked
		blockReason = result.BlockReason()
	}

	// Record asynchronously — never block the response on history writes.
	label := principal.Label(r)
	ua := r.Header.Get("User-Agent")
	go func() {
		rec := history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemNPM,
			PackageName:    pkg,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		}
		if err := a.recorder.Record(context.Background(), rec); err != nil {
			a.logger.Error("record download history", "err", err)
		}
	}()

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistoryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistoryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}

	// Redirect to the upstream tarball URL directly.
	upstreamURL := fmt.Sprintf("%s/%s/-/%s", a.upstreamURL, pkg, file)
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

// fetchMetadata returns metadata bytes, using cache when available.
func (a *Adapter) fetchMetadata(ctx context.Context, pkg string) ([]byte, error) {
	cacheKey := "npm:meta:" + pkg

	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			return cached, nil
		}
	}

	upstreamURL := fmt.Sprintf("%s/%s", a.upstreamURL, pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}

	if a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, metaCacheTTL)
	}

	return body, nil
}

// extractVersion parses the version from a tarball filename.
// e.g. "lodash-4.17.21.tgz" → "4.17.21" (when pkg="lodash")
// e.g. "pkg-name-1.0.0.tgz" → "1.0.0"
func extractVersion(pkg, file string) string {
	// file is like "{basename}-{version}.tgz"
	// basename is the last path component of pkg (handles scoped packages).
	basename := pkg
	if idx := strings.LastIndex(pkg, "/"); idx >= 0 {
		basename = pkg[idx+1:]
	}
	prefix := basename + "-"
	if !strings.HasPrefix(file, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(file, prefix)
	return strings.TrimSuffix(rest, ".tgz")
}
