package gomod

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
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
)

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
	r.HandleFunc("/gomod/*", a.handle)
}

func (a *Adapter) handle(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	mod, version, ok := parseVersionRequest(rel)
	if !ok {
		a.proxy(w, r, rel)
		return
	}

	pf := facts.PackageFacts{Ecosystem: facts.EcosystemGoMod, Name: mod, Version: version}
	if info, err := a.fetchInfo(r.Context(), mod, version); err == nil {
		pf.Version = info.Version
		pf.PublishedAt = info.Time
		pf.AgeDays = time.Since(info.Time).Hours() / 24
		version = info.Version
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
	a.record(r, mod, version, outcome, blockReason)

	if result.Decision == policy.DecisionBlock {
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		http.Error(w, fmt.Sprintf("403 Forbidden: %s", blockReason), http.StatusForbidden)
		return
	}
	a.proxy(w, r, rel)
}

func (a *Adapter) fetchInfo(ctx context.Context, mod, version string) (*moduleInfo, error) {
	infoPath := mod + "/@v/" + version + ".info"
	if version == "latest" {
		infoPath = mod + "/@latest"
	}
	body, status, _, err := a.fetchURL(ctx, infoPath)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("info returned %d", status)
	}
	var info moduleInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	return &info, nil
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
		a.logger.ErrorContext(r.Context(), "gomod upstream request", "path", rel, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (a *Adapter) fetchURL(ctx context.Context, rel string) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/"+rel, nil)
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

func (a *Adapter) record(r *http.Request, pkg, version string, outcome history.Outcome, blockReason string) {
	if a.recorder == nil {
		return
	}
	label := principal.Label(r)
	ua := r.Header.Get("User-Agent")
	go func() {
		_ = a.recorder.Record(context.Background(), history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemGoMod,
			PackageName:    pkg,
			Version:        version,
			Outcome:        outcome,
			BlockReason:    blockReason,
			UserAgent:      ua,
		})
	}()
}

type moduleInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

func parseVersionRequest(rel string) (mod, version string, ok bool) {
	const marker = "/@v/"
	idx := strings.Index(rel, marker)
	if idx < 0 {
		if strings.HasSuffix(rel, "/@latest") {
			return strings.TrimSuffix(rel, "/@latest"), "latest", true
		}
		return "", "", false
	}
	mod = rel[:idx]
	file := rel[idx+len(marker):]
	switch {
	case strings.HasSuffix(file, ".info"):
		return mod, strings.TrimSuffix(file, ".info"), true
	case strings.HasSuffix(file, ".mod"):
		return mod, strings.TrimSuffix(file, ".mod"), true
	case strings.HasSuffix(file, ".zip"):
		return mod, strings.TrimSuffix(file, ".zip"), true
	default:
		return "", "", false
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
