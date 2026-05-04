package facts

import "time"

// Ecosystem identifies the package manager / registry.
type Ecosystem string

const (
	EcosystemNPM      Ecosystem = "npm"
	EcosystemPyPI     Ecosystem = "pypi"
	EcosystemRubyGems Ecosystem = "rubygems"
	EcosystemComposer Ecosystem = "composer"
	EcosystemHomebrew Ecosystem = "homebrew"
	EcosystemDocker   Ecosystem = "docker"
	EcosystemMaven    Ecosystem = "maven"
	EcosystemNuGet    Ecosystem = "nuget"
	EcosystemCargo    Ecosystem = "cargo"
	EcosystemGoMod    Ecosystem = "gomod"
)

// TrustLevel defines an ordered hierarchy of publisher trust.
// Higher value = more trusted.
type TrustLevel int

const (
	TrustUnknown          TrustLevel = 0
	TrustUser             TrustLevel = 1
	TrustCIBotOIDC        TrustLevel = 2
	TrustTrustedPublisher TrustLevel = 3
)

func (t TrustLevel) String() string {
	switch t {
	case TrustUser:
		return "user"
	case TrustCIBotOIDC:
		return "ci_oidc"
	case TrustTrustedPublisher:
		return "trusted_publisher"
	default:
		return "unknown"
	}
}

// TrustSignals captures all observable trust evidence for a specific version.
// Fields are pointers so that nil means "not fetched / unavailable",
// distinguishing it from an explicit false.
type TrustSignals struct {
	Publisher  *PublisherSignal
	Provenance *ProvenanceSignal
	Signature  *SignatureSignal
}

type PublisherSignal struct {
	// ID is the account identifier (npm username, PyPI username, etc.)
	ID               string
	Level            TrustLevel
	TwoFactorEnabled *bool // nil = unknown
}

type ProvenanceSignal struct {
	Present     bool
	BuilderType string // e.g. "https://github.com/actions/runner"
	SourceRepo  string // e.g. "github.com/lodash/lodash"
	Verified    bool
}

type SignatureSignal struct {
	Present  bool
	Verified bool
}

// PackageFacts is the normalized fact set used by the policy engine.
type PackageFacts struct {
	Ecosystem   Ecosystem
	Name        string
	Version     string
	PublishedAt time.Time
	AgeDays     float64
	// DownloadCount is the download count reported by the registry.
	// Semantics vary: npm provides last-30-day downloads; RubyGems provides
	// lifetime total downloads. nil means the registry does not expose this data.
	DownloadCount *int64
	IsDeprecated  bool
	Yanked        bool
	Trust         *TrustSignals

	// Extension point: populated by future malware-DB integration.
	Malicious []MaliciousIndicator
}

type MaliciousIndicator struct {
	Source     string
	AdvisoryID string
	Severity   string
}
