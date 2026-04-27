package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS download_records (
    id              TEXT    NOT NULL PRIMARY KEY,
    principal_label TEXT,
    ecosystem       TEXT    NOT NULL,
    package_name    TEXT    NOT NULL,
    version         TEXT    NOT NULL,
    outcome         TEXT    NOT NULL CHECK (outcome IN ('allowed','blocked')),
    block_reason    TEXT,
    policy_version  INTEGER,
    client_ip       TEXT,
    user_agent      TEXT,
    occurred_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_dr_pkg     ON download_records (ecosystem, package_name, version, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_dr_label   ON download_records (principal_label, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_dr_outcome ON download_records (outcome, occurred_at DESC);
`

// Open opens a SQLite database at dsn.
// Use ":memory:" for in-process ephemeral storage (tests).
// Returns nil, nil when dsn is empty — callers must handle a nil *sql.DB.
func Open(dsn string) (*sql.DB, error) {
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite serialises writes; keep the pool at 1.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return nil, fmt.Errorf("set wal: %w", err)
	}
	return db, nil
}

// Migrate creates the schema (idempotent — uses IF NOT EXISTS).
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
