package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

func validPostgres() PostgreSQL {
	return PostgreSQL{Host: "::1", Port: 5432, Database: "db/name ?", Username: "db user@", Password: "pass ?@:/#'", SSLMode: "require", MaxOpen: 30, MaxIdle: 0}
}

func TestDatabaseConnectionValidationAndEscaping(t *testing.T) {
	original := validPostgres()
	if err := original.Validate(); err != nil {
		t.Fatal(err)
	}
	parsed, err := pgx.ParseConfig(original.DSN())
	if err != nil || parsed.Host != original.Host || parsed.Database != original.Database || parsed.User != original.Username || parsed.Password != original.Password {
		t.Fatal("DSN did not preserve escaped fields")
	}
	for _, mutate := range []func(*PostgreSQL){func(p *PostgreSQL) { p.Host = "" }, func(p *PostgreSQL) { p.Host = "host:5432" }, func(p *PostgreSQL) { p.Port = 0 }, func(p *PostgreSQL) { p.Port = 65536 }, func(p *PostgreSQL) { p.MaxIdle = 31 }, func(p *PostgreSQL) { p.MaxIdle = -1 }, func(p *PostgreSQL) { p.MaxOpen = 0 }, func(p *PostgreSQL) { p.SSLMode = "invalid" }} {
		p := original
		mutate(&p)
		if p.Validate() == nil {
			t.Fatal("invalid connection accepted")
		}
	}
	if original.MaxIdle != 0 {
		t.Fatal("zero idle limit changed")
	}
}

func TestManagedDatabaseEncryptedPersistence(t *testing.T) {
	dir := t.TempDir()
	change := DatabaseChange{ID: "migration-1", Target: validPostgres(), State: "completed"}
	if err := WriteDatabaseChange(dir, DatabaseActiveFile, change); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, DatabaseActiveFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(change.Target.Password)) || json.Valid(raw) {
		t.Fatal("database credentials stored in plaintext")
	}
	restored, err := ReadDatabaseChange(dir, DatabaseActiveFile)
	if err != nil || restored.Target != change.Target {
		t.Fatal("encrypted roundtrip failed")
	}
	cfg := Config{DataDir: dir, DatabaseDriver: "sqlite", DatabaseDSN: "original.db"}
	if err = cfg.loadManagedDatabase(); err != nil || cfg.DatabaseDriver != "postgres" || cfg.DatabaseMaxIdle != 0 || cfg.DatabaseMaxOpen != 30 {
		t.Fatal("active connection not loaded")
	}
	projected, _ := json.Marshal(restored.Target.Public())
	if bytes.Contains(projected, []byte("password")) || bytes.Contains(projected, []byte(change.Target.Password)) {
		t.Fatal("password exposed")
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(filepath.Join(dir, DatabaseActiveFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadDatabaseChange(dir, DatabaseActiveFile); err == nil {
		t.Fatal("corrupt database config accepted")
	}
}
