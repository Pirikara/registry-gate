package db_test

import (
	"testing"

	"github.com/pirikara/registry-gate/internal/db"
)

func TestOpen_EmptyDSN_ReturnsNil(t *testing.T) {
	database, err := db.Open("")
	if err != nil {
		t.Fatalf("Open(\"\") returned error: %v", err)
	}
	if database != nil {
		t.Fatal("Open(\"\") should return nil db for log-only mode")
	}
}

func TestOpen_Memory(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("Open(\":memory:\"): %v", err)
	}
	defer database.Close()
	if err := database.Ping(); err != nil {
		t.Fatalf("Ping after open: %v", err)
	}
}

func TestMigrate_CreatesSchema(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	_, err = database.Exec(`
		INSERT INTO download_records (id, ecosystem, package_name, version, outcome)
		VALUES ('test-uuid', 'npm', 'lodash', '4.0.0', 'allowed')`)
	if err != nil {
		t.Fatalf("insert after migrate: %v — schema may be missing", err)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM download_records`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("got %d rows, want 1", count)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := db.Migrate(database); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("second Migrate (idempotency check): %v", err)
	}
}
