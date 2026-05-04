package nuget

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

	"github.com/pirikara/registry-gate/internal/adapter/principal"
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
)

const serviceCacheTTL = 5 * time.Minute

type Adapter struct {
	upstreamIndexURL string
	proxyBase        string
	policyEng        *policy.Engine
	recorder         history.Recorder
	cache            cache.Cache
	httpClient       *http.Client
	logger           *slog.Logger
}

type Config struct {
	UpstreamIndexURL string
	ProxyBase        string
	PolicyEng        *policy.Engine
	Recorder         history.Recorder
	Cache            cache.Cache
	HTTPClient       *http.Client
	Logger           *slog.Logger
}

func NewAdapter(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		upstreamIndexURL: strings.TrimRight(cfg.UpstreamIndexURL, "/"),
		proxyBase:        strings.TrimRight(cfg.ProxyBase, "/"),
		policyEng:        cfg.PolicyEng,
		recorder:         cfg.Recorder,
		cache:            cfg.Cache,
		httpClient:       cfg.HTTPClient,
		logger:           cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

func (a *Adapter) Mount(r chi.Router) {
	r.Get("/nuget/v3/index.json", a.handleServiceIndex)
	r.HandleFunc("/nuget/v3-flatcontainer/*", a.handleFlatContainer)
	r.Get("/nuget/v3/registration/*", a.handleRegistration)
}

func (a *Adapter) handleServiceIndex(w http.ResponseWriter, r *http.Request) {
	raw, err := a.fetchServiceIndex(r.Context())
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	var doc serviceIndex
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}
	for i := range doc.Resources {
		typ := resourceString(doc.Resources[i], "@type")
		switch {
		case hasType(typ, "PackageBaseAddress"):
			doc.Resources[i]["@id"] = a.proxyBase + "/nuget/v3-flatcontainer/"
		case hasType(typ, "RegistrationsBaseUrl"):
			doc.Resources[i]["@id"] = a.proxyBase + "/nuget/v3/registration/"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (a *Adapter) handleRegistration(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	res, err := a.resources(r.Context())
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	body, status, contentType, err := a.fetchURL(r.Context(), strings.TrimRight(res.RegistrationBase, "/")+"/"+rel)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	if status != http.StatusOK {
		w.WriteHeader(status)
		_, _ = w.Write(body)
		return
	}
	body = []byte(strings.ReplaceAll(string(body), strings.TrimRight(res.FlatContainerBase, "/")+"/", a.proxyBase+"/nuget/v3-flatcontainer/"))
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(body)
}

func (a *Adapter) handleFlatContainer(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	id, version, ok := parseFlatPackagePath(rel)
	if !ok {
		a.proxyFlat(w, r, rel)
		return
	}

	pf := facts.PackageFacts{Ecosystem: facts.EcosystemNuGet, Name: id, Version: version}
	if meta, err := a.fetchVersionMetadata(r.Context(), id, version); err == nil {
		pf.PublishedAt = meta.Published
		pf.AgeDays = time.Since(meta.Published).Hours() / 24
		pf.Yanked = !meta.Listed
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
	a.record(r, id, version, outcome, blockReason)

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}
	a.proxyFlat(w, r, rel)
}

func (a *Adapter) proxyFlat(w http.ResponseWriter, r *http.Request, rel string) {
	res, err := a.resources(r.Context())
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	a.proxyURL(w, r, strings.TrimRight(res.FlatContainerBase, "/")+"/"+rel)
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
		a.logger.ErrorContext(r.Context(), "nuget upstream request", "url", upstream, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (a *Adapter) fetchVersionMetadata(ctx context.Context, id, version string) (*versionMetadata, error) {
	res, err := a.resources(ctx)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("%s/%s/%s.json", strings.TrimRight(res.RegistrationBase, "/"), strings.ToLower(id), strings.ToLower(version))
	body, status, _, err := a.fetchURL(ctx, u)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("registration returned %d", status)
	}
	var raw struct {
		Listed    *bool  `json:"listed"`
		Published string `json:"published"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	published, err := time.Parse(time.RFC3339Nano, raw.Published)
	if err != nil {
		return nil, err
	}
	listed := true
	if raw.Listed != nil {
		listed = *raw.Listed
	}
	return &versionMetadata{Published: published, Listed: listed}, nil
}

func (a *Adapter) fetchServiceIndex(ctx context.Context) ([]byte, error) {
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, "nuget:service-index"); err == nil {
			return cached, nil
		}
	}
	body, status, _, err := a.fetchURL(ctx, a.upstreamIndexURL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("service index returned %d", status)
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, "nuget:service-index", body, serviceCacheTTL)
	}
	return body, nil
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

func (a *Adapter) resources(ctx context.Context) (*serviceResources, error) {
	raw, err := a.fetchServiceIndex(ctx)
	if err != nil {
		return nil, err
	}
	var doc serviceIndex
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	res := &serviceResources{}
	for _, r := range doc.Resources {
		id := resourceString(r, "@id")
		typ := resourceString(r, "@type")
		switch {
		case res.FlatContainerBase == "" && hasType(typ, "PackageBaseAddress"):
			res.FlatContainerBase = strings.TrimRight(id, "/")
		case hasType(typ, "RegistrationsBaseUrl/3.6.0"):
			res.RegistrationBase = strings.TrimRight(id, "/")
		case res.RegistrationBase == "" && hasType(typ, "RegistrationsBaseUrl"):
			res.RegistrationBase = strings.TrimRight(id, "/")
		}
	}
	if res.FlatContainerBase == "" || res.RegistrationBase == "" {
		return nil, fmt.Errorf("nuget service index missing required resources")
	}
	return res, nil
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
			Ecosystem:      facts.EcosystemNuGet,
			PackageName:    pkg,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()
}

type serviceIndex struct {
	Version   string           `json:"version,omitempty"`
	Resources []map[string]any `json:"resources"`
	Context   any              `json:"@context,omitempty"`
}

type serviceResources struct {
	FlatContainerBase string
	RegistrationBase  string
}

type versionMetadata struct {
	Published time.Time
	Listed    bool
}

func hasType(got, want string) bool {
	return got == want || strings.HasPrefix(got, want+"/")
}

func resourceString(res map[string]any, key string) string {
	if s, ok := res[key].(string); ok {
		return s
	}
	return ""
}

func parseFlatPackagePath(rel string) (id, version string, ok bool) {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) != 3 || !strings.HasSuffix(strings.ToLower(parts[2]), ".nupkg") {
		return "", "", false
	}
	return parts[0], parts[1], true
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
