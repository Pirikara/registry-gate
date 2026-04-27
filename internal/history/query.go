package history

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/pirikara/registory-gate/internal/facts"
)

type Filter struct {
	Ecosystem   facts.Ecosystem
	PackageName string
	From        time.Time
	To          time.Time
	Outcome     Outcome
	Limit       int
	Offset      int
}

type Querier struct {
	db *sql.DB
}

func NewQuerier(db *sql.DB) *Querier { return &Querier{db: db} }

func (q *Querier) List(ctx context.Context, f Filter) ([]Record, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	clauses := []string{"1=1"}
	args := []any{}

	if f.Ecosystem != "" {
		clauses = append(clauses, "ecosystem = ?")
		args = append(args, string(f.Ecosystem))
	}
	if f.PackageName != "" {
		clauses = append(clauses, "package_name = ?")
		args = append(args, f.PackageName)
	}
	if !f.From.IsZero() {
		clauses = append(clauses, "occurred_at >= ?")
		args = append(args, f.From.UTC().Format(time.RFC3339))
	}
	if !f.To.IsZero() {
		clauses = append(clauses, "occurred_at < ?")
		args = append(args, f.To.UTC().Format(time.RFC3339))
	}
	if f.Outcome != "" {
		clauses = append(clauses, "outcome = ?")
		args = append(args, string(f.Outcome))
	}

	query := fmt.Sprintf(`
		SELECT id, principal_label, ecosystem, package_name, version,
		       outcome, block_reason, occurred_at
		FROM download_records
		WHERE %s
		ORDER BY occurred_at DESC
		LIMIT ? OFFSET ?`, strings.Join(clauses, " AND "))
	args = append(args, f.Limit, f.Offset)

	rows, err := q.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list downloads: %w", err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var (
			rec         Record
			idStr       string
			label       *string
			blockReason *string
			occurredAt  string
		)
		if err := rows.Scan(
			&idStr, &label,
			&rec.Ecosystem, &rec.PackageName, &rec.Version,
			&rec.Outcome, &blockReason, &occurredAt,
		); err != nil {
			return nil, err
		}
		rec.ID = uuid.MustParse(idStr)
		if label != nil {
			rec.PrincipalLabel = *label
		}
		if blockReason != nil {
			rec.BlockReason = *blockReason
		}
		if t, err := time.Parse(time.RFC3339, occurredAt); err == nil {
			rec.OccurredAt = t
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}
