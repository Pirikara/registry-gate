package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
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
	provenanceCacheTTL = 24 * time.Hour // PEP 740 bundles never change once published
	baselineLimit      = 5              // most-recent N other versions used for trust baseline
)

// Adapter handles PyPI registry proxy requests.
// Implements the PyPI JSON API: GET /pypi/<pkg>/json
// and tarball redirect:         GET /packages/<filename>
type Adapter struct {
	upstreamURL string
	proxyBase   string
	policyEng   *policy.Engine
	recorder    history.Recorder
	cache       cache.Cache
	httpClient  *http.Client
	logger      *slog.Logger
}

type Config struct {
	UpstreamURL string
	ProxyBase   string
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
		proxyBase:   strings.TrimRight(cfg.ProxyBase, "/"),
		policyEng:   cfg.PolicyEng,
		recorder:    cfg.Recorder,
		cache:       cfg.Cache,
		httpClient:  cfg.HTTPClient,
		logger:      cfg.Logger,
	}
}

// NewTestAdapter is an alias for NewAdapter; provided for clarity in tests.
var NewTestAdapter = NewAdapter

// Mount registers routes on the given router.
//
//	GET /pypi/{pkg}/json         → JSON API (programmatic metadata)
//	GET /pypi/simple/{pkg}/      → PEP 503 Simple API (pip / poetry / uv)
//	GET /simple/{pkg}/           → same, alternate mount point
//	GET /packages/{file}         → tarball redirect with policy enforcement
func (a *Adapter) Mount(r chi.Router) {
	r.Get("/pypi/{pkg}/json", a.handleJSONAPI)
	r.Get("/pypi/simple/{pkg}/", a.handleSimplePackage)
	r.Get("/pypi/simple/{pkg}", a.handleSimplePackage)
	r.Get("/simple/{pkg}/", a.handleSimplePackage)
	r.Get("/simple/{pkg}", a.handleSimplePackage)
	r.Get("/packages/{file}", a.handlePackage)
}

func (a *Adapter) handleJSONAPI(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "pkg")
	ctx := r.Context()

	raw, err := a.fetchJSONAPI(ctx, pkg)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch pypi json api", "pkg", pkg, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	resp, err := ParseJSONAPI(raw)
	if err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	// Evaluate policy for every version; remove blocked ones from releases map.
	for version := range resp.Releases {
		pf, err := resp.ToPackageFacts(version)
		if err != nil {
			continue
		}
		result, err := a.policyEng.Evaluate(ctx, *pf)
		if err != nil {
			continue
		}
		if result.Decision == policy.DecisionBlock {
			delete(resp.Releases, version)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *Adapter) handlePackage(w http.ResponseWriter, r *http.Request) {
	file := chi.URLParam(r, "file")
	ctx := r.Context()

	pkgName, version := parseFilename(file)

	var pf *facts.PackageFacts
	var baseline []facts.PackageFacts
	if pkgName != "" && version != "" {
		if raw, err := a.fetchJSONAPI(ctx, pkgName); err == nil {
			if resp, err := ParseJSONAPI(raw); err == nil {
				pf, _ = resp.ToPackageFacts(version)
				if pf != nil {
					a.attachTrust(ctx, pf, resp)
					baseline = a.buildBaseline(ctx, resp, version)
				}
			}
		}
	}
	if pf == nil {
		pf = &facts.PackageFacts{
			Ecosystem: facts.EcosystemPyPI,
			Name:      pkgName,
			Version:   version,
		}
	}

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
		rec := history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemPyPI,
			PackageName:    pkgName,
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

	// files.pythonhosted.org is the actual CDN for PyPI packages.
	upstreamURL := "https://files.pythonhosted.org/packages/" + file
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (a *Adapter) fetchJSONAPI(ctx context.Context, pkg string) ([]byte, error) {
	cacheKey := "pypi:json:" + pkg
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			return cached, nil
		}
	}

	url := fmt.Sprintf("%s/pypi/%s/json", a.upstreamURL, pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
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
		return nil, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, metaCacheTTL)
	}
	return body, nil
}

// attachTrust populates pf.Trust by fetching the PEP 740 provenance for the
// version's primary file. A 404 from the integrity endpoint is a meaningful
// signal (file uploaded without trusted publishing) and is recorded as
// NoProvenanceTrust. Network errors leave Trust nil.
func (a *Adapter) attachTrust(ctx context.Context, pf *facts.PackageFacts, resp *JSONAPIResponse) {
	filename := resp.PrimaryFilename(pf.Version)
	if filename == "" {
		return
	}
	bundle, present, err := a.fetchProvenance(ctx, pf.Name, pf.Version, filename)
	if err != nil {
		return
	}
	if !present {
		pf.Trust = NoProvenanceTrust()
		return
	}
	pf.Trust = bundle.ToTrustSignals()
}

// buildBaseline picks the most-recent N other versions and fetches their
// trust signals so trust_downgrade has something to compare against.
// Versions are ordered by upload time; the target version is excluded.
func (a *Adapter) buildBaseline(ctx context.Context, resp *JSONAPIResponse, target string) []facts.PackageFacts {
	type verAt struct {
		version    string
		uploadedAt time.Time
	}
	var all []verAt
	for v := range resp.Releases {
		if v == target {
			continue
		}
		files := resp.Releases[v]
		if len(files) == 0 {
			continue
		}
		ts := files[0].UploadTimeISO
		if ts == "" {
			ts = files[0].UploadTime
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t, _ = time.Parse("2006-01-02T15:04:05", ts)
		}
		all = append(all, verAt{v, t})
	}
	// Sort newest first.
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].uploadedAt.After(all[j-1].uploadedAt); j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	if len(all) > baselineLimit {
		all = all[:baselineLimit]
	}

	out := make([]facts.PackageFacts, 0, len(all))
	for _, v := range all {
		bf, err := resp.ToPackageFacts(v.version)
		if err != nil {
			continue
		}
		a.attachTrust(ctx, bf, resp)
		out = append(out, *bf)
	}
	return out
}

// fetchProvenance hits the PyPI integrity endpoint for a specific file.
// Returns (bundle, true, nil) on 200, (nil, false, nil) on 404, error otherwise.
func (a *Adapter) fetchProvenance(ctx context.Context, pkg, version, filename string) (*PEP740Bundle, bool, error) {
	cacheKey := fmt.Sprintf("pypi:prov:%s/%s/%s", pkg, version, filename)
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			if string(cached) == "404" {
				return nil, false, nil
			}
			var b PEP740Bundle
			if err := json.Unmarshal(cached, &b); err == nil {
				return &b, true, nil
			}
		}
	}

	url := fmt.Sprintf("%s/integrity/%s/%s/%s/provenance", a.upstreamURL, pkg, version, filename)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		if a.cache != nil {
			_ = a.cache.Set(ctx, cacheKey, []byte("404"), provenanceCacheTTL)
		}
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	var b PEP740Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, false, fmt.Errorf("parse provenance: %w", err)
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, provenanceCacheTTL)
	}
	return &b, true, nil
}

// fileURLRe matches file URLs in Simple API responses (HTML and JSON).
// Captures: (1) filename, (2) hash fragment (optional).
// Example: https://files.pythonhosted.org/packages/ba/bb/dfa.../requests-2.28.0.whl#sha256=abc
// Uses greedy [^"]* to consume up to the last "/" before the filename.
var fileURLRe = regexp.MustCompile(
	`https://files\.pythonhosted\.org/packages/[^"]*?/([^/"#\s]+)(#[^"'\s]*)`)

// handleSimplePackage proxies the PEP 503 Simple Repository API for one package.
// File URLs are rewritten to route through this proxy so tarball downloads are
// intercepted for policy enforcement. pip, poetry, and uv all use this endpoint.
func (a *Adapter) handleSimplePackage(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "pkg")
	ctx := r.Context()

	upstreamURL := fmt.Sprintf("%s/simple/%s/", a.upstreamURL, pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch simple api", "pkg", pkg, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "read upstream body", http.StatusBadGateway)
		return
	}

	body = rewriteSimpleURLs(body, a.proxyBase)

	for k, vals := range resp.Header {
		if strings.EqualFold(k, "content-length") {
			continue // length changed after rewrite
		}
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// rewriteSimpleURLs replaces pythonhosted.org file URLs with proxy URLs so
// package managers download through the proxy's /packages/{file} endpoint.
func rewriteSimpleURLs(body []byte, proxyBase string) []byte {
	base := strings.TrimRight(proxyBase, "/")
	result := fileURLRe.ReplaceAll(body, []byte(base+"/packages/$1$2"))
	return result
}

// parseFilename extracts package name and version from a wheel or sdist filename.
func parseFilename(file string) (name, version string) {
	switch {
	case strings.HasSuffix(file, ".whl"):
		// wheel: {name}-{version}-py3-none-any.whl
		parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
		if len(parts) >= 2 {
			return normalizeName(parts[0]), parts[1]
		}
	case strings.HasSuffix(file, ".tar.gz"):
		base := strings.TrimSuffix(file, ".tar.gz")
		if idx := strings.LastIndex(base, "-"); idx >= 0 {
			return normalizeName(base[:idx]), base[idx+1:]
		}
	case strings.HasSuffix(file, ".zip"):
		base := strings.TrimSuffix(file, ".zip")
		if idx := strings.LastIndex(base, "-"); idx >= 0 {
			return normalizeName(base[:idx]), base[idx+1:]
		}
	}
	return "", ""
}

// normalizeName converts underscores/dots to hyphens per PEP 503.
func normalizeName(s string) string {
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return strings.ToLower(s)
}
