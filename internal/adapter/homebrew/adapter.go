package homebrew

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


const formulaCacheTTL = 5 * time.Minute

// FormulaInfo holds the subset of the Homebrew API formula response we care about.
type FormulaInfo struct {
	Name     string `json:"name"`
	Versions struct {
		Stable string `json:"stable"`
	} `json:"versions"`
	Desc        string `json:"desc"`
	HomeURL     string `json:"homepage"`
	Tap         string `json:"tap"`
}

// Adapter handles Homebrew bottle requests.
//
// When HOMEBREW_BOTTLE_DOMAIN is set to the Registory Gate proxy URL,
// Homebrew fetches bottles from:
//   GET /bottles/{formula}--{version}.{arch}.bottle.tar.gz
//
// The upstream is the GitHub Container Registry (ghcr.io) where
// Homebrew core bottles are published.
type Adapter struct {
	upstreamURL   string
	formulaAPIURL string
	policyEng     *policy.Engine
	recorder      history.Recorder
	cache         cache.Cache
	httpClient    *http.Client
	logger        *slog.Logger
}

type Config struct {
	UpstreamURL   string
	FormulaAPIURL string
	PolicyEng     *policy.Engine
	Recorder      history.Recorder
	Cache         cache.Cache
	HTTPClient    *http.Client
	Logger        *slog.Logger
}

func NewAdapter(cfg Config) *Adapter {
	if cfg.UpstreamURL == "" {
		cfg.UpstreamURL = "https://ghcr.io/v2/homebrew/core"
	}
	if cfg.FormulaAPIURL == "" {
		cfg.FormulaAPIURL = "https://formulae.brew.sh/api/formula"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Adapter{
		upstreamURL:   strings.TrimRight(cfg.UpstreamURL, "/"),
		formulaAPIURL: strings.TrimRight(cfg.FormulaAPIURL, "/"),
		policyEng:     cfg.PolicyEng,
		recorder:      cfg.Recorder,
		cache:         cfg.Cache,
		httpClient:    cfg.HTTPClient,
		logger:        cfg.Logger,
	}
}

var NewTestAdapter = NewAdapter

// Mount registers the Homebrew bottle route.
func (a *Adapter) Mount(r chi.Router) {
	r.Get("/bottles/*", a.handleBottle)
}

func (a *Adapter) handleBottle(w http.ResponseWriter, r *http.Request) {
	// chi wildcard includes the leading slash — strip it.
	bottleFile := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	ctx := r.Context()

	formula, version := ParseBottleFilename(bottleFile)

	pf := &facts.PackageFacts{
		Ecosystem: facts.EcosystemHomebrew,
		Name:      formula,
		Version:   version,
	}

	// Enrich from formula API if name was parsed.
	if formula != "" {
		if info, err := a.fetchFormulaInfo(ctx, formula); err == nil {
			pf.Trust = extractTrust(info)
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
			Ecosystem:      facts.EcosystemHomebrew,
			PackageName:    formula,
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

	// Redirect to the GHCR bottle URL.
	// Homebrew bottles on GHCR follow: /v2/homebrew/core/{formula}/blobs/{sha256digest}
	// We don't have the digest at this point, so we redirect to the raw GitHub Releases CDN.
	upstreamURL := fmt.Sprintf(
		"https://github.com/orgs/Homebrew/packages/container/homebrew-core%%2F%s/bottles/%s",
		strings.ReplaceAll(formula, "-", "+"),
		bottleFile,
	)
	// Simpler: just redirect to the standard GHCR pull URL that Homebrew itself uses.
	upstreamURL = fmt.Sprintf("%s/%s/blobs/download?filename=%s",
		a.upstreamURL, formula, bottleFile)
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (a *Adapter) fetchFormulaInfo(ctx context.Context, formula string) (*FormulaInfo, error) {
	key := "homebrew:formula:" + formula
	if a.cache != nil {
		if cached, err := a.cache.Get(ctx, key); err == nil {
			var info FormulaInfo
			if err := json.Unmarshal(cached, &info); err == nil {
				return &info, nil
			}
		}
	}

	url := fmt.Sprintf("%s/%s.json", a.formulaAPIURL, formula)
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
		return nil, fmt.Errorf("formula api %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var info FormulaInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	if a.cache != nil {
		_ = a.cache.Set(ctx, key, body, formulaCacheTTL)
	}
	return &info, nil
}

// extractTrust builds minimal trust signals from formula info.
// Homebrew core bottles are always built by the official CI (GitHub Actions),
// so we mark them as TrustTrustedPublisher when they come from homebrew-core.
func extractTrust(info *FormulaInfo) *facts.TrustSignals {
	if info == nil {
		return nil
	}
	level := facts.TrustUser
	if info.Tap == "homebrew/core" || info.Tap == "" {
		level = facts.TrustTrustedPublisher
	}
	return &facts.TrustSignals{
		Publisher: &facts.PublisherSignal{
			ID:    info.Tap,
			Level: level,
		},
	}
}

// ParseBottleFilename extracts formula name and version from a bottle filename.
// Homebrew uses the separator "--" between formula and version:
//   "git--2.42.0.arm64_sonoma.bottle.tar.gz"       → ("git", "2.42.0")
//   "node--21.0.0.arm64_sonoma.bottle.1.tar.gz"    → ("node", "21.0.0")
//   "python@3.11--3.11.6.arm64_sonoma.bottle.tar.gz" → ("python@3.11", "3.11.6")
func ParseBottleFilename(filename string) (formula, version string) {
	base := strings.TrimSuffix(filename, ".tar.gz")

	parts := strings.SplitN(base, "--", 2)
	if len(parts) != 2 {
		return base, ""
	}
	formula = parts[0]

	// version is the leading dot-separated numeric segments before the OS/arch part.
	// e.g. "2.42.0.arm64_sonoma.bottle" → "2.42.0"
	segs := strings.Split(parts[1], ".")
	var vParts []string
	for _, seg := range segs {
		if isAllDigits(seg) {
			vParts = append(vParts, seg)
		} else {
			break
		}
	}
	if len(vParts) > 0 {
		version = strings.Join(vParts, ".")
	}
	return
}

func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
