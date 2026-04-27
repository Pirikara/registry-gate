package history

import (
	"context"
	"log/slog"
	"time"
)

// LogRecorder emits structured JSON download events via slog.
// It is always active and is the primary audit trail.
type LogRecorder struct{ logger *slog.Logger }

func NewLogRecorder(l *slog.Logger) *LogRecorder { return &LogRecorder{logger: l} }

func (r *LogRecorder) Record(_ context.Context, rec Record) error {
	if rec.OccurredAt.IsZero() {
		rec.OccurredAt = time.Now()
	}
	attrs := []any{
		"ecosystem", string(rec.Ecosystem),
		"package", rec.PackageName,
		"version", rec.Version,
		"outcome", string(rec.Outcome),
		"occurred_at", rec.OccurredAt.UTC().Format(time.RFC3339),
	}
	if rec.BlockReason != "" {
		attrs = append(attrs, "block_reason", rec.BlockReason)
	}
	if rec.PrincipalLabel != "" {
		attrs = append(attrs, "principal", rec.PrincipalLabel)
	}
	if rec.ClientIP != nil {
		attrs = append(attrs, "client_ip", rec.ClientIP.String())
	}
	r.logger.Info("download", attrs...)
	return nil
}

// MultiRecorder fans out to multiple Recorders.
// Errors are logged but do not stop subsequent recorders.
type MultiRecorder []Recorder

func (m MultiRecorder) Record(ctx context.Context, rec Record) error {
	for _, r := range m {
		if err := r.Record(ctx, rec); err != nil {
			slog.Error("recorder error", "err", err)
		}
	}
	return nil
}
