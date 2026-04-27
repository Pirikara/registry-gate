package testutil

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/pirikara/registory-gate/internal/db"
)

// OpenSQLite opens an in-memory SQLite database and runs migrations.
// The connection is closed automatically when the test ends.
func OpenSQLite(t *testing.T) *sql.DB {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := db.Migrate(database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database
}
