package history_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pirikara/registory-gate/internal/facts"
	"github.com/pirikara/registory-gate/internal/history"
	"github.com/pirikara/registory-gate/internal/testutil"
)

func TestRecorder_Record_Allowed(t *testing.T) {
	db := testutil.OpenSQLite(t)
	ctx := context.Background()
	recorder := history.NewRecorder(db)

	rec := history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "lodash",
		Version:     "4.17.21",
		Outcome:     history.OutcomeAllowed,
		ClientIP:    net.ParseIP("192.168.1.1"),
		UserAgent:   "npm/9.0.0",
		OccurredAt:  time.Now(),
	}

	if err := recorder.Record(ctx, rec); err != nil {
		t.Fatalf("record: %v", err)
	}

	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM download_records WHERE package_name='lodash' AND outcome='allowed'`,
	).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 record, got %d", count)
	}
}

func TestRecorder_Record_Blocked(t *testing.T) {
	db := testutil.OpenSQLite(t)
	ctx := context.Background()
	recorder := history.NewRecorder(db)

	rec := history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "evil-pkg",
		Version:     "1.0.0",
		Outcome:     history.OutcomeBlocked,
		BlockReason: "[cd] cooldown: evil-pkg@1.0.0 was published 1.0 day(s) ago",
		OccurredAt:  time.Now(),
	}

	if err := recorder.Record(ctx, rec); err != nil {
		t.Fatalf("record: %v", err)
	}

	var reason string
	err := db.QueryRowContext(ctx,
		`SELECT block_reason FROM download_records WHERE package_name='evil-pkg'`,
	).Scan(&reason)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if reason == "" {
		t.Error("expected block_reason to be persisted")
	}
}

func TestRecorder_Record_Anonymous(t *testing.T) {
	db := testutil.OpenSQLite(t)
	ctx := context.Background()
	recorder := history.NewRecorder(db)

	rec := history.Record{
		Ecosystem:   facts.EcosystemNPM,
		PackageName: "chalk",
		Version:     "5.0.0",
		Outcome:     history.OutcomeAllowed,
		OccurredAt:  time.Now(),
	}

	if err := recorder.Record(ctx, rec); err != nil {
		t.Fatalf("record anonymous: %v", err)
	}

	var label *string
	err := db.QueryRowContext(ctx,
		`SELECT principal_label FROM download_records WHERE package_name='chalk'`,
	).Scan(&label)
	if err != nil {
		t.Fatal(err)
	}
	if label != nil {
		t.Error("expected NULL principal_label for anonymous download")
	}
}

func TestRecorder_Record_WithPrincipalLabel(t *testing.T) {
	db := testutil.OpenSQLite(t)
	ctx := context.Background()
	recorder := history.NewRecorder(db)

	rec := history.Record{
		PrincipalLabel: "alice@example.com",
		Ecosystem:      facts.EcosystemNPM,
		PackageName:    "react",
		Version:        "19.0.0",
		Outcome:        history.OutcomeAllowed,
		OccurredAt:     time.Now(),
	}
	if err := recorder.Record(ctx, rec); err != nil {
		t.Fatal(err)
	}

	var label string
	err := db.QueryRowContext(ctx,
		`SELECT principal_label FROM download_records WHERE package_name='react'`,
	).Scan(&label)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if label != "alice@example.com" {
		t.Errorf("expected label 'alice@example.com', got %q", label)
	}
}
