package maven

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/pirikara/registry-gate/internal/adapter/principal"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
)

// Adapter handles Maven repository layout requests under /maven2.
type Adapter struct {
	upstreamURL string
	policyEng   *policy.Engine
	recorder    history.Recorder
	httpClient  *http.Client
	logger      *slog.Logger
}

type Config struct {
	UpstreamURL string
	PolicyEng   *policy.Engine
	Recorder    history.Recorder
	HTTPClient  *http.Client
	Logger      *slog.Logger
}

func NewAdapter(cfg Config) *Adapter {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		upstreamURL: strings.TrimRight(cfg.UpstreamURL, "/"),
		policyEng:   cfg.PolicyEng,
		recorder:    cfg.Recorder,
		httpClient:  cfg.HTTPClient,
		logger:      cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

func (a *Adapter) Mount(r chi.Router) {
	r.HandleFunc("/maven2/*", a.handle)
}

func (a *Adapter) handle(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	ref, ok := parseArtifactPath(rel)
	if !ok {
		a.proxy(w, r, rel)
		return
	}

	pf := facts.PackageFacts{
		Ecosystem: facts.EcosystemMaven,
		Name:      ref.Package,
		Version:   ref.Version,
	}
	if publishedAt, err := a.fetchPublishedAt(r.Context(), rel); err == nil {
		pf.PublishedAt = publishedAt
		pf.AgeDays = time.Since(publishedAt).Hours() / 24
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
	a.record(r, ref.Package, ref.Version, outcome, blockReason)

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}

	a.proxy(w, r, rel)
}

func (a *Adapter) fetchPublishedAt(ctx context.Context, rel string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, a.upstreamURL+"/"+rel, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return time.Time{}, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	return http.ParseTime(resp.Header.Get("Last-Modified"))
}

func (a *Adapter) proxy(w http.ResponseWriter, r *http.Request, rel string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, a.upstreamURL+"/"+rel, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "maven upstream request", "path", rel, "err", err)
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
			Ecosystem:      facts.EcosystemMaven,
			PackageName:    pkg,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()
}

type artifactRef struct {
	Package string
	Version string
}

func parseArtifactPath(rel string) (artifactRef, bool) {
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	if len(parts) < 4 {
		return artifactRef{}, false
	}
	file := parts[len(parts)-1]
	if file == "" || strings.HasPrefix(file, "maven-metadata.xml") {
		return artifactRef{}, false
	}
	artifact := parts[len(parts)-3]
	version := parts[len(parts)-2]
	if artifact == "" || version == "" {
		return artifactRef{}, false
	}
	group := strings.Join(parts[:len(parts)-3], ".")
	if group == "" {
		return artifactRef{}, false
	}
	return artifactRef{Package: group + ":" + artifact, Version: version}, true
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
