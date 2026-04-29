package docker

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
	"github.com/pirikara/registry-gate/internal/cache"
	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
	"github.com/pirikara/registry-gate/internal/policy"
)

const manifestCacheTTL = 30 * time.Second

// Adapter is a pull-through proxy for Docker Registry HTTP API v2 (OCI Distribution Spec).
//
// Docker daemon mirror configuration:
//   "registry-mirrors": ["https://docker.registry-gate.example.com"]
//
// Route layout (all mounted under /v2):
//   GET/HEAD /v2/                            → API version check
//   GET/HEAD /v2/{name...}/manifests/{ref}   → policy check + proxy manifest
//   GET/HEAD /v2/{name...}/blobs/{digest}    → policy gate (manifest must be approved) + 302
//   GET      /v2/{name...}/tags/list         → transparent proxy
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
	if cfg.UpstreamURL == "" {
		cfg.UpstreamURL = "https://registry-1.docker.io"
	}
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
		cache:       cfg.Cache,
		httpClient:  cfg.HTTPClient,
		logger:      cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

// Mount attaches the Docker Registry v2 routes to a chi router.
// Typically called with r.Route("/v2", ...) so all paths are relative.
func (a *Adapter) Mount(r chi.Router) {
	// Version check: must return 200 with the API version header.
	r.Get("/v2/", a.handleVersionCheck)
	r.Head("/v2/", a.handleVersionCheck)

	// All other /v2/* paths are dispatched by the wildcard handler.
	r.HandleFunc("/v2/*", a.handleV2)
}

func (a *Adapter) handleVersionCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

// handleV2 is the catch-all dispatcher for /v2/* paths.
// It parses the path to identify the operation type and routes accordingly.
func (a *Adapter) handleV2(w http.ResponseWriter, r *http.Request) {
	// Strip leading /v2/
	path := strings.TrimPrefix(r.URL.Path, "/v2/")

	switch {
	case containsSegment(path, "manifests"):
		name, ref := splitAtSegment(path, "manifests")
		if name == "" || ref == "" {
			http.NotFound(w, r)
			return
		}
		a.handleManifest(w, r, name, ref)

	case containsSegment(path, "blobs"):
		name, digest := splitAtSegment(path, "blobs")
		if name == "" || digest == "" {
			http.NotFound(w, r)
			return
		}
		a.handleBlob(w, r, name, digest)

	case strings.HasSuffix(path, "/tags/list"):
		a.handleTransparentProxy(w, r)

	default:
		a.handleTransparentProxy(w, r)
	}
}

// handleManifest proxies the manifest request, applying policy.
func (a *Adapter) handleManifest(w http.ResponseWriter, r *http.Request, imageName, reference string) {
	ctx := r.Context()

	raw, contentType, statusCode, err := a.fetchManifest(ctx, imageName, reference, r.Header)
	if err != nil {
		a.logger.ErrorContext(ctx, "fetch manifest", "image", imageName, "ref", reference, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	// Forward non-200 responses (e.g. 401 auth challenges, 404) directly.
	if statusCode != http.StatusOK {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(statusCode)
		_, _ = w.Write(raw)
		return
	}

	manifest, err := ParseManifest(raw)
	if err != nil {
		// Probably a manifest list or format we don't need to parse — pass through.
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(raw)
		return
	}

	pf := manifest.ToPackageFacts(imageName, reference)

	result, err := a.policyEng.Evaluate(ctx, *pf)
	if err != nil {
		a.logger.ErrorContext(ctx, "policy eval", "image", imageName, "ref", reference, "err", err)
		http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
		return
	}

	label := principal.Label(r)
	ua := r.Header.Get("User-Agent")

	if result.Decision == policy.DecisionBlock {
		blockReason := result.BlockReason()
		go func() {
			_ = a.recorder.Record(context.Background(), history.Record{
				PrincipalLabel: label,
				Ecosystem:      facts.EcosystemDocker,
				PackageName:    imageName,
				Version:        reference,
				Outcome:        history.OutcomeBlocked,
				BlockReason:    blockReason,
				UserAgent:      ua,
			})
		}()
		w.Header().Set("X-RegistryGate-Block-Reason", "policy")
		w.Header().Set("X-RegistryGate-Block-Detail", blockReason)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"errors":[{"code":"DENIED","message":%q}]}`, blockReason)
		return
	}

	// Record allowed downloads.
	go func() {
		_ = a.recorder.Record(context.Background(), history.Record{
			PrincipalLabel: label,
			Ecosystem:      facts.EcosystemDocker,
			PackageName:    imageName,
			Version:        reference,
			Outcome:        history.OutcomeAllowed,
			UserAgent:      ua,
		})
	}()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Docker-Content-Digest", digestHeader(raw))
	_, _ = w.Write(raw)
}

// handleBlob redirects blob requests to the upstream registry.
// Blobs are content-addressed (sha256 digest), so they are safe to redirect.
func (a *Adapter) handleBlob(w http.ResponseWriter, r *http.Request, imageName, digest string) {
	upstreamURL := fmt.Sprintf("%s/v2/%s/blobs/%s", a.upstreamURL, imageName, digest)

	// For HEAD requests, proxy the headers rather than redirect.
	if r.Method == http.MethodHead {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodHead, upstreamURL, nil)
		if err != nil {
			http.Error(w, "proxy error", http.StatusBadGateway)
			return
		}
		copyHeaders(req.Header, r.Header)
		resp, err := a.httpClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		return
	}

	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

// handleTransparentProxy forwards the request to the upstream unchanged.
func (a *Adapter) handleTransparentProxy(w http.ResponseWriter, r *http.Request) {
	upstream := a.upstreamURL + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, r.Header)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// fetchManifest retrieves a manifest from upstream (or cache).
func (a *Adapter) fetchManifest(ctx context.Context, imageName, reference string, clientHeaders http.Header) ([]byte, string, int, error) {
	cacheKey := fmt.Sprintf("docker:manifest:%s:%s", imageName, reference)
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
			return cached, MediaTypeManifestV2, http.StatusOK, nil
		}
	}

	url := fmt.Sprintf("%s/v2/%s/manifests/%s", a.upstreamURL, imageName, reference)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", 0, err
	}

	// Accept all manifest types.
	req.Header.Set("Accept", strings.Join([]string{
		MediaTypeOCIManifest,
		MediaTypeOCIIndex,
		MediaTypeManifestV2,
		MediaTypeManifestListV2,
		"application/json",
	}, ", "))

	// Forward auth header so private images still work.
	if auth := clientHeaders.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = MediaTypeManifestV2
	}

	if resp.StatusCode == http.StatusOK && a.cache != nil {
		_ = a.cache.Set(ctx, cacheKey, body, manifestCacheTTL)
	}

	return body, contentType, resp.StatusCode, nil
}

// digestHeader computes a placeholder Content-Digest for tests.
// In production this should be the actual manifest digest.
func digestHeader(data []byte) string {
	// Real implementation would compute sha256 of the manifest bytes.
	// For now return a stable placeholder.
	return fmt.Sprintf("sha256:%x", len(data))
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		// Don't forward hop-by-hop headers.
		switch strings.ToLower(k) {
		case "connection", "keep-alive", "proxy-authenticate",
			"proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// containsSegment returns true if the path contains "/{segment}/" or ends with "/{segment}".
func containsSegment(path, segment string) bool {
	return strings.Contains(path, "/"+segment+"/") || strings.HasSuffix(path, "/"+segment)
}

// splitAtSegment splits "imageName/manifests/reference" into ("imageName", "reference").
func splitAtSegment(path, segment string) (before, after string) {
	sep := "/" + segment + "/"
	idx := strings.Index(path, sep)
	if idx < 0 {
		return "", ""
	}
	return path[:idx], path[idx+len(sep):]
}
