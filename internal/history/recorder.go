package history

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/pirikara/registory-gate/internal/facts"
)

// Record represents a single download event.
type Record struct {
	ID uuid.UUID `json:"id"`
	// PrincipalLabel is a free-form attribution string sourced from an
	// upstream auth proxy header (e.g. X-Forwarded-User). Empty for
	// unauthenticated requests.
	PrincipalLabel string          `json:"principalLabel,omitempty"`
	Ecosystem      facts.Ecosystem `json:"ecosystem"`
	PackageName    string          `json:"packageName"`
	Version        string          `json:"version"`
	Outcome        Outcome         `json:"outcome"`
	BlockReason    string          `json:"blockReason,omitempty"`
	PolicyVersion  *int            `json:"policyVersion,omitempty"`
	ClientIP       net.IP          `json:"-"`
	UserAgent      string          `json:"userAgent,omitempty"`
	OccurredAt     time.Time       `json:"occurredAt"`
}

type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeBlocked Outcome = "blocked"
)

// Recorder is the interface for writing download events.
type Recorder interface {
	Record(ctx context.Context, rec Record) error
}

// DBRecorder writes download events to a SQLite database.
type DBRecorder struct {
	db *sql.DB
}

func NewRecorder(db *sql.DB) *DBRecorder {
	return &DBRecorder{db: db}
}

// NoopRecorder discards all events; useful in tests.
type NoopRecorder struct{}

func NewNoopRecorder() *NoopRecorder { return &NoopRecorder{} }

func (NoopRecorder) Record(_ context.Context, _ Record) error { return nil }

func (r *DBRecorder) Record(ctx context.Context, rec Record) error {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	if rec.OccurredAt.IsZero() {
		rec.OccurredAt = time.Now()
	}

	var clientIP *string
	if rec.ClientIP != nil {
		s := rec.ClientIP.String()
		clientIP = &s
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO download_records
			(id, principal_label, ecosystem, package_name, version,
			 outcome, block_reason, policy_version, client_ip, user_agent, occurred_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		rec.ID.String(),
		nullString(rec.PrincipalLabel),
		string(rec.Ecosystem),
		rec.PackageName,
		rec.Version,
		string(rec.Outcome),
		nullString(rec.BlockReason),
		rec.PolicyVersion,
		clientIP,
		nullString(rec.UserAgent),
		rec.OccurredAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("record download: %w", err)
	}
	return nil
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
