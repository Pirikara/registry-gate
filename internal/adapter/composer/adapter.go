package composer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/principal"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
)

const (
	rootCacheTTL = 5 * time.Minute
	p2CacheTTL   = 60 * time.Second
)

// Adapter proxies Composer/Packagist repository metadata and dist downloads.
//
// Composer clients should point the Packagist repository at the proxy base URL.
// The adapter serves:
//
//	GET /packages.json                 -> repository root metadata
//	GET /p2/{vendor}/{package}.json    -> filtered package metadata
//	GET /p2/{vendor}/{package}~dev.json -> filtered dev metadata
//	GET /composer/dist/{file}          -> policy check + redirect to dist URL
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
	if cfg.UpstreamURL == "" {
		cfg.UpstreamURL = "https://repo.packagist.org"
	}
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

var NewTestAdapter = NewAdapter

func (a *Adapter) Mount(r chi.Router) {
	r.Get("/packages.json", a.handlePackagesJSON)
	r.Get("/packages/list.json", a.handleTransparent)
	r.Get("/p2/*", a.handleP2)
	r.Get("/composer/dist/{file}", a.handleDist)
}

func (a *Adapter) handlePackagesJSON(w http.ResponseWriter, r *http.Request) {
	body, status, err := a.fetchRoot(r.Context())
	if err != nil {
		a.logger.ErrorContext(r.Context(), "fetch composer packages root", "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}

	var root map[string]any
	if err := json.Unmarshal(body, &root); err == nil {
		root["metadata-url"] = "/p2/%package%.json"
		delete(root, "providers-url")
		delete(root, "provider-includes")
		delete(root, "notify-batch")
		body, _ = json.Marshal(root)
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (a *Adapter) handleP2(w http.ResponseWriter, r *http.Request) {
	p2Path := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	pkg, ok := packageNameFromP2Path(p2Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	raw, status, err := a.fetchP2(r.Context(), p2Path)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "fetch composer p2 metadata", "pkg", pkg, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write(raw)
		return
	}

	meta, err := ParseP2Metadata(raw)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "parse composer p2 metadata", "pkg", pkg, "err", err)
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}

	for packageName, versions := range meta.Packages {
		allowed := versions[:0]
		for _, version := range versions {
			pf := version.ToPackageFacts(packageName)
			result, err := a.policyEng.Evaluate(r.Context(), *pf)
			if err == nil && result.Decision == policy.DecisionBlock {
				continue
			}
			version.RewriteDownloadURLs(a.proxyBase)
			allowed = append(allowed, version)
		}
		meta.Packages[packageName] = allowed
	}

	body, err := meta.Encode()
	if err != nil {
		http.Error(w, "encode metadata response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (a *Adapter) handleDist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	packageName := r.URL.Query().Get("package")
	version := r.URL.Query().Get("version")
	upstreamURL, err := decodeUpstreamURL(r.URL.Query().Get("url"))
	if err != nil || upstreamURL == "" {
		http.Error(w, "invalid dist url", http.StatusBadRequest)
		return
	}

	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemComposer,
		Name:      packageName,
		Version:   version,
	}
	if packageName != "" && version != "" {
		if enriched := a.fetchVersionFacts(ctx, packageName, version); enriched != nil {
			pf = enriched
		}
	}

	result, err := a.policyEng.Evaluate(ctx, *pf)
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
			Ecosystem:      facts.EcosystemComposer,
			PackageName:    packageName,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}

	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (a *Adapter) handleTransparent(w http.ResponseWriter, r *http.Request) {
	body, status, err := a.fetch(r.Context(), r.URL.RequestURI())
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (a *Adapter) fetchVersionFacts(ctx context.Context, packageName, version string) *facts.PackageFacts {
	p2Path := packageName + ".json"
	raw, status, err := a.fetchP2(ctx, p2Path)
	if err != nil || status != http.StatusOK {
		return nil
	}
	meta, err := ParseP2Metadata(raw)
	if err != nil {
		return nil
	}
	for name, versions := range meta.Packages {
		for _, v := range versions {
			if v.Version() == version {
				return v.ToPackageFacts(name)
			}
		}
	}
	return nil
}

func (a *Adapter) fetchRoot(ctx context.Context) ([]byte, int, error) {
	cacheKey := "composer:root"
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			return cached, http.StatusOK, nil
		}
	}
	body, status, err := a.fetch(ctx, "/packages.json")
	if err != nil || status != http.StatusOK {
		return body, status, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, rootCacheTTL)
	}
	return body, status, nil
}

func (a *Adapter) fetchP2(ctx context.Context, p2Path string) ([]byte, int, error) {
	cacheKey := "composer:p2:" + p2Path
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			return cached, http.StatusOK, nil
		}
	}
	body, status, err := a.fetch(ctx, "/p2/"+p2Path)
	if err != nil || status != http.StatusOK {
		return body, status, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, p2CacheTTL)
	}
	return body, status, nil
}

func (a *Adapter) fetch(ctx context.Context, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func packageNameFromP2Path(p string) (string, bool) {
	if !strings.HasSuffix(p, ".json") {
		return "", false
	}
	name := strings.TrimSuffix(p, ".json")
	name = strings.TrimSuffix(name, "~dev")
	if strings.Count(name, "/") != 1 {
		return "", false
	}
	if unescaped, err := url.PathUnescape(name); err == nil {
		name = strings.ToLower(unescaped)
	}
	return name, true
}

func encodeUpstreamURL(u string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(u))
}

func decodeUpstreamURL(encoded string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
