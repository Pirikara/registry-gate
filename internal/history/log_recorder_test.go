package history_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/pirikara/registry-gate/internal/facts"
	"github.com/pirikara/registry-gate/internal/history"
)

func newJSONLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func parseLogEntry(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("parse log entry: %v (raw: %q)", err, buf.String())
	}
	return entry
}

func TestLogRecorder_BasicFields(t *testing.T) {
	var buf bytes.Buffer
	r := history.NewLogRecorder(newJSONLogger(&buf))

	_ = r.Record(context.Background(), history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "lodash",
		Version:     "4.17.21",
		Outcome:     history.OutcomeAllowed,
		OccurredAt:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	entry := parseLogEntry(t, &buf)
	if entry["ecosystem"] != "npm" {
		t.Errorf("ecosystem: got %v", entry["ecosystem"])
	}
	if entry["package"] != "lodash" {
		t.Errorf("package: got %v", entry["package"])
	}
	if entry["version"] != "4.17.21" {
		t.Errorf("version: got %v", entry["version"])
	}
	if entry["outcome"] != "allowed" {
		t.Errorf("outcome: got %v", entry["outcome"])
	}
}

func TestLogRecorder_ZeroOccurredAt_FilledAutomatically(t *testing.T) {
	var buf bytes.Buffer
	r := history.NewLogRecorder(newJSONLogger(&buf))

	before := time.Now().Truncate(time.Second)
	_ = r.Record(context.Background(), history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "chalk",
		Version:     "5.0.0",
		Outcome:     history.OutcomeAllowed,
		// OccurredAt intentionally zero
	})
	after := time.Now().Add(time.Second)

	entry := parseLogEntry(t, &buf)
	raw, ok := entry["occurred_at"].(string)
	if !ok {
		t.Fatal("occurred_at missing from log")
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("parse occurred_at %q: %v", raw, err)
	}
	if parsed.Before(before) || parsed.After(after) {
		t.Errorf("occurred_at %v out of range [%v, %v]", parsed, before, after)
	}
}

func TestLogRecorder_BlockReason_IncludedWhenSet(t *testing.T) {
	var buf bytes.Buffer
	r := history.NewLogRecorder(newJSONLogger(&buf))

	_ = r.Record(context.Background(), history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "evil",
		Version:     "1.0.0",
		Outcome:     history.OutcomeBlocked,
		BlockReason: "cooldown",
		OccurredAt:  time.Now(),
	})

	entry := parseLogEntry(t, &buf)
	if entry["block_reason"] != "cooldown" {
		t.Errorf("block_reason: got %v", entry["block_reason"])
	}
}

func TestLogRecorder_BlockReason_OmittedWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	r := history.NewLogRecorder(newJSONLogger(&buf))

	_ = r.Record(context.Background(), history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "allowed-pkg",
		Version:     "1.0.0",
		Outcome:     history.OutcomeAllowed,
		OccurredAt:  time.Now(),
	})

	entry := parseLogEntry(t, &buf)
	if _, exists := entry["block_reason"]; exists {
		t.Error("block_reason should be absent when empty")
	}
}

func TestLogRecorder_PrincipalAndClientIP(t *testing.T) {
	var buf bytes.Buffer
	r := history.NewLogRecorder(newJSONLogger(&buf))

	_ = r.Record(context.Background(), history.Record{
		Ecosystem:      facts.EcosystemNPM,
		PackageName:    "react",
		Version:        "19.0.0",
		Outcome:        history.OutcomeAllowed,
		PrincipalLabel: "alice@example.com",
		ClientIP:       net.ParseIP("10.0.0.1"),
		OccurredAt:     time.Now(),
	})

	entry := parseLogEntry(t, &buf)
	if entry["principal"] != "alice@example.com" {
		t.Errorf("principal: got %v", entry["principal"])
	}
	if entry["client_ip"] != "10.0.0.1" {
		t.Errorf("client_ip: got %v", entry["client_ip"])
	}
}

func TestMultiRecorder_FansOutToAll(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	multi := history.MultiRecorder{
		history.NewLogRecorder(newJSONLogger(&buf1)),
		history.NewLogRecorder(newJSONLogger(&buf2)),
	}

	_ = multi.Record(context.Background(), history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "express",
		Version:     "5.0.0",
		Outcome:     history.OutcomeAllowed,
		OccurredAt:  time.Now(),
	})

	if buf1.Len() == 0 {
		t.Error("first recorder did not receive event")
	}
	if buf2.Len() == 0 {
		t.Error("second recorder did not receive event")
	}
}
