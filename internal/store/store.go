package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

func Open(cfg Config) (*Store, error) {
	driver := strings.ToLower(cfg.Driver)
	if driver == "" {
		driver = "sqlite"
	}
	if driver == "postgres" || driver == "postgresql" {
		driver = "pgx"
	}
	if driver != "sqlite" && driver != "pgx" {
		return nil, fmt.Errorf("unsupported database driver %q", cfg.Driver)
	}
	if cfg.DSN == "" {
		return nil, fmt.Errorf("database DSN is required")
	}
	db, err := sql.Open(driver, cfg.DSN)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, driver: driver}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(10)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err == nil {
		err = s.migrate(ctx)
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB              { return s.db }
func (s *Store) Driver() string           { return s.driver }
func (s *Store) Bind(query string) string { return s.bind(query) }

func (s *Store) bind(query string) string {
	if s.driver != "pgx" {
		return query
	}
	var b strings.Builder
	n := 0
	for _, c := range query {
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (s *Store) migrate(ctx context.Context) error {
	if s.driver == "sqlite" {
		for _, q := range []string{"PRAGMA busy_timeout = 10000", "PRAGMA journal_mode = WAL", "PRAGMA foreign_keys = ON"} {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				return err
			}
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = CreateSchema(ctx, tx, s.driver); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSchema also supports the empty-target migration transaction.
func CreateSchema(ctx context.Context, tx *sql.Tx, driver string) error {
	s := &Store{driver: driver}
	queries := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL, username_key TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')), disabled INTEGER NOT NULL DEFAULT 0, token_version BIGINT NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS records (collection TEXT NOT NULL, id TEXT NOT NULL, owner_id TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, version BIGINT NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(collection,id))`,
		`CREATE INDEX IF NOT EXISTS records_owner ON records(collection,owner_id,created_at)`,
		`CREATE TABLE IF NOT EXISTS subscription_bindings (subscription_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, plan_id TEXT NOT NULL, UNIQUE(user_id,plan_id))`,
		`CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS audit_created ON audit_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS metrics (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS metrics_server_time ON metrics(server_id,recorded_at)`,
		`CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, server_id TEXT NOT NULL, actor_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, input TEXT NOT NULL, result TEXT NOT NULL, error TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS tasks_server_time ON tasks(server_id,created_at)`,
		`CREATE INDEX IF NOT EXISTS tasks_status_updated ON tasks(status,updated_at)`,
		`CREATE TABLE IF NOT EXISTS traffic_cursors(server_id TEXT NOT NULL,counter_key TEXT NOT NULL,generation TEXT NOT NULL,last_value BIGINT NOT NULL,sampled_at BIGINT NOT NULL,PRIMARY KEY(server_id,counter_key))`,
		`CREATE TABLE IF NOT EXISTS traffic_ledger(id TEXT PRIMARY KEY,server_id TEXT NOT NULL,subscription_id TEXT NOT NULL,owner_id TEXT NOT NULL DEFAULT '',email TEXT NOT NULL,direction TEXT NOT NULL,raw_bytes BIGINT NOT NULL,factor DOUBLE PRECISION NOT NULL,weighted_bytes DOUBLE PRECISION NOT NULL,sampled_at BIGINT NOT NULL,gap INTEGER NOT NULL,gap_reason TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS traffic_ledger_subscription ON traffic_ledger(subscription_id,sampled_at)`,
		`CREATE INDEX IF NOT EXISTS traffic_ledger_sampled ON traffic_ledger(sampled_at)`,
		`CREATE INDEX IF NOT EXISTS traffic_ledger_server_sampled ON traffic_ledger(server_id,sampled_at)`,
		`CREATE INDEX IF NOT EXISTS traffic_ledger_owner_sampled ON traffic_ledger(owner_id,sampled_at)`,
	}
	for _, q := range queries {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?) ON CONFLICT(version) DO NOTHING`), 1, stamp(time.Now())); err != nil {
		return err
	}
	return nil
}

func stamp(t time.Time) string      { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }
func parseStamp(v string) time.Time { t, _ := time.Parse(time.RFC3339Nano, v); return t }

func translate(err error) error {
	if err == nil {
		return nil
	}
	if err == sql.ErrNoRows {
		return ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unique constraint") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "constraint failed: unique") {
		return fmt.Errorf("%w", ErrConflict)
	}
	return err
}

func (s *Store) Initialized(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM settings WHERE key='_internal.initialized')`).Scan(&count)
	return count > 0, err
}

func (s *Store) GetSetting(ctx context.Context, key string, out any) error {
	var raw string
	if err := s.db.QueryRowContext(ctx, s.bind(`SELECT value FROM settings WHERE key=?`), key).Scan(&raw); err != nil {
		return translate(err)
	}
	return s.decodeJSON([]byte(raw), out)
}

func (s *Store) SetSetting(ctx context.Context, key string, value any) error {
	if strings.TrimSpace(key) == "" || strings.HasPrefix(key, "_internal.") {
		return ErrInvalid
	}
	raw, err := s.encodeJSON(value)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`), key, string(raw), stamp(time.Now()))
	return err
}

func (s *Store) ListSettings(ctx context.Context) (map[string]json.RawMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]json.RawMessage)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(key, "_internal.") {
			var decoded json.RawMessage
			if err := s.decodeJSON([]byte(value), &decoded); err != nil {
				return nil, err
			}
			result[key] = decoded
		}
	}
	return result, rows.Err()
}
