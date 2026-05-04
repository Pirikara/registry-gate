package cargo

import (
	"bufio"
	"context"
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

const indexCacheTTL = 60 * time.Second

type Adapter struct {
	indexURL   string
	apiURL     string
	proxyBase  string
	policyEng  *policy.Engine
	recorder   history.Recorder
	cache      cache.Cache
	httpClient *http.Client
	logger     *slog.Logger
}

type Config struct {
	IndexURL   string
	APIURL     string
	ProxyBase  string
	PolicyEng  *policy.Engine
	Recorder   history.Recorder
	Cache      cache.Cache
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func NewAdapter(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		indexURL:   strings.TrimRight(cfg.IndexURL, "/"),
		apiURL:     strings.TrimRight(cfg.APIURL, "/"),
		proxyBase:  strings.TrimRight(cfg.ProxyBase, "/"),
		policyEng:  cfg.PolicyEng,
		recorder:   cfg.Recorder,
		cache:      cfg.Cache,
		httpClient: cfg.HTTPClient,
		logger:     cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

func (a *Adapter) Mount(r chi.Router) {
	r.Get("/cargo/index/config.json", a.handleConfig)
	r.Get("/cargo/index/*", a.handleIndex)
	r.HandleFunc("/cargo/api/v1/crates/*", a.handleAPI)
}

func (a *Adapter) handleConfig(w http.ResponseWriter, r *http.Request) {
	body, status, contentType, err := a.fetchURL(r.Context(), a.indexURL+"/config.json")
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}
	cfg["dl"] = a.proxyBase + "/cargo/api/v1/crates/{crate}/{version}/download"
	if _, ok := cfg["api"]; ok {
		cfg["api"] = a.proxyBase + "/cargo/api"
	}
	w.Header().Set("Content-Type", contentType)
	_ = json.NewEncoder(w).Encode(cfg)
}

func (a *Adapter) handleIndex(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	a.proxyURL(w, r, a.indexURL+"/"+rel)
}

func (a *Adapter) handleAPI(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	crate, version, ok := parseDownloadPath(rel)
	if !ok {
		a.proxyURL(w, r, a.apiURL+"/api/v1/crates/"+rel)
		return
	}

	pf := facts.PackageFacts{Ecosystem: facts.EcosystemCargo, Name: crate, Version: version}
	if entry, err := a.fetchIndexEntry(r.Context(), crate, version); err == nil {
		pf.PublishedAt = entry.PubTime
		pf.AgeDays = time.Since(entry.PubTime).Hours() / 24
		pf.Yanked = entry.Yanked
	}

	result, err := a.policyEng.Evaluate(r.Context(), pf)
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
	a.record(r, crate, version, outcome, blockReason)

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}

	upstream, err := a.downloadURL(r.Context(), crate, version)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, upstream, http.StatusFound)
}

func (a *Adapter) fetchIndexEntry(ctx context.Context, crate, version string) (*indexEntry, error) {
	body, err := a.fetchIndexFile(ctx, crate)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		var e indexEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if e.Version == version {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("version not found")
}

func (a *Adapter) fetchIndexFile(ctx context.Context, crate string) ([]byte, error) {
	rel := indexPath(crate)
	key := "cargo:index:" + rel
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, key); err == nil {
			return cached, nil
		}
	}
	body, status, _, err := a.fetchURL(ctx, a.indexURL+"/"+rel)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("index returned %d", status)
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, key, body, indexCacheTTL)
	}
	return body, nil
}

func (a *Adapter) downloadURL(ctx context.Context, crate, version string) (string, error) {
	body, status, _, err := a.fetchURL(ctx, a.indexURL+"/config.json")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("config returned %d", status)
	}
	var cfg struct {
		DL string `json:"dl"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", err
	}
	if cfg.DL == "" {
		return "", fmt.Errorf("cargo config missing dl")
	}
	u := cfg.DL
	replacements := map[string]string{
		"{crate}":   url.PathEscape(crate),
		"{version}": url.PathEscape(version),
	}
	for k, v := range replacements {
		u = strings.ReplaceAll(u, k, v)
	}
	if strings.Contains(u, "{") {
		return "", fmt.Errorf("unsupported cargo dl template %q", cfg.DL)
	}
	if !strings.Contains(cfg.DL, "{crate}") && !strings.Contains(cfg.DL, "{version}") {
		u = strings.TrimRight(cfg.DL, "/") + "/" + url.PathEscape(crate) + "/" + url.PathEscape(version) + "/download"
	}
	return u, nil
}

func (a *Adapter) fetchURL(ctx context.Context, u string) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, "", err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, resp.Header.Get("Content-Type"), err
}

func (a *Adapter) proxyURL(w http.ResponseWriter, r *http.Request, upstream string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "cargo upstream request", "url", upstream, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (a *Adapter) record(r *http.Request, pkg, version string, outcome history.Outcome, blockReason string) {
	if a.recorder == nil {
		return
	}
	label := principal.Label(r)
	ua := r.Header.Get("User-Agent")
	go func() {
		_ = a.recorder.Record(context.Background(), history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemCargo,
			PackageName:    pkg,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()
}

type indexEntry struct {
	Name    string    `json:"name"`
	Version string    `json:"vers"`
	Yanked  bool      `json:"yanked"`
	PubTime time.Time `json:"pubtime"`
}

func parseDownloadPath(rel string) (crate, version string, ok bool) {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) == 3 && parts[2] == "download" {
		return parts[0], parts[1], true
	}
	return "", "", false
}

func indexPath(crate string) string {
	name := strings.ToLower(crate)
	switch len(name) {
	case 1:
		return "1/" + name
	case 2:
		return "2/" + name
	case 3:
		return "3/" + name[:1] + "/" + name
	default:
		return name[:2] + "/" + name[2:4] + "/" + name
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
