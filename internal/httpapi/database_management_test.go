package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestDatabaseStatusPermissionsAndValidation(t *testing.T) {
	a, h, token := controllerFixture(t)
	for _, route := range []struct{ method, path string }{{"GET", "/api/database/status"}, {"POST", "/api/database/test"}, {"POST", "/api/database/migrate"}, {"DELETE", "/api/database/migrate"}} {
		requireStatus(t, controllerRequest(t, h, route.method, route.path, "", nil), 401)
	}
	u := store.User{ID: "db-member", Username: "db-member", Role: "user", PasswordHash: "test"}
	if err := a.DB.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	member, _ := a.Signer.Issue(u.ID, 0)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/database/status", member, nil), 403)
	res := controllerRequest(t, h, "GET", "/api/database/status", token, nil)
	requireStatus(t, res, 200)
	body := responseMap(t, res)
	if text(body, "driver") != "sqlite" || number(body, "sizeBytes") <= 0 || number(body, "maxOpen") != 1 {
		t.Fatal("inaccurate database status", body)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/database/test", token, map[string]any{"host": "localhost", "password": "secret-test"}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/database/migrate", token, map[string]any{"confirm": "wrong"}), 400)
	if _, err := os.Stat(filepath.Join(a.Config.DataDir, config.DatabasePendingFile)); !os.IsNotExist(err) {
		t.Fatal("invalid request persisted credentials")
	}
	created := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "token.create", "params": map[string]any{"name": "database-api-test", "scopes": []string{"read", "write"}}})
	requireStatus(t, created, 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/database/migrate", text(responseMap(t, created), "token"), nil), 403)
}

// Each subtest creates a dedicated database on an explicitly configured test
// PostgreSQL instance. No existing database or schema is modified.
func migrationPostgres(t *testing.T) config.PostgreSQL {
	t.Helper()
	dsn := os.Getenv("ASWIRED_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ASWIRED_TEST_POSTGRES_DSN unset")
	}
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL DSN")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "aswired_migration_" + strings.ReplaceAll(newID(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec("CREATE DATABASE " + quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec("DROP DATABASE " + quoted + " WITH (FORCE)"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	return config.PostgreSQL{Host: parsed.Host, Port: int(parsed.Port), Database: name, Username: parsed.User, Password: parsed.Password, SSLMode: "disable", MaxOpen: 7, MaxIdle: 0}
}

func TestDatabaseMigrationPostgres(t *testing.T) {
	t.Run("copy_verify_resume_activate", func(t *testing.T) {
		target := migrationPostgres(t)
		a, h, token := controllerFixture(t)
		ctx := context.Background()
		a.Config.DatabaseDriver = "sqlite"
		a.Config.DatabaseDSN = filepath.Join(a.Config.DataDir, "test.db")
		user, err := a.DB.UserByUsername(ctx, "test-admin")
		if err != nil {
			t.Fatal(err)
		}
		user.TokenVersion = 1 << 54
		if err = a.DB.UpdateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		token, _ = a.Signer.Issue(user.ID, user.TokenVersion)
		_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "encrypted", Data: map[string]any{"password": "retained-secret", "name": "节点"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.DB.DB().Exec("INSERT INTO traffic_cursors VALUES('s','c','g',9007199254740993,1)"); err != nil {
			t.Fatal(err)
		}
		res := controllerRequest(t, h, "POST", "/api/database/test", token, target)
		requireStatus(t, res, 200)
		requireStatus(t, controllerRequest(t, h, "POST", "/api/database/migrate", token, map[string]any{"confirm": "迁移到 PostgreSQL", "target": target}), 202)
		select {
		case <-a.RestartRequested():
		default:
			t.Fatal("restart was not requested")
		}
		switched, err := a.ApplyDatabaseMigration(ctx)
		if err != nil || !switched {
			t.Fatal("migration failed", err)
		}
		active, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabaseActiveFile)
		if err != nil || active == nil || active.BackupID == "" {
			t.Fatal("active connection missing", err)
		}
		dst, err := store.Open(store.Config{Driver: "postgres", DSN: target.DSN()})
		if err != nil {
			t.Fatal(err)
		}
		defer dst.Close()
		key, err := config.LoadOrCreateSecret(filepath.Join(a.Config.DataDir, "data-encryption.key"))
		if err != nil {
			t.Fatal(err)
		}
		if err = dst.SetEncryptionKey(key); err != nil {
			t.Fatal(err)
		}
		row, err := dst.GetRecord(ctx, "servers", "encrypted")
		if err != nil || text(row.Data, "password") != "retained-secret" {
			t.Fatal("encrypted data not preserved", err)
		}
		copied, err := dst.UserByID(ctx, user.ID)
		if err != nil || copied.TokenVersion != user.TokenVersion {
			t.Fatal("BIGINT changed")
		}
		var counter int64
		if err = dst.DB().QueryRow("SELECT last_value FROM traffic_cursors").Scan(&counter); err != nil || counter != 9007199254740993 {
			t.Fatal("traffic counter changed", err)
		}
		raw, err := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", active.BackupID+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := migrationManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = copyDatabaseManifest(ctx, dst.DB(), *active, manifest); err != nil {
			t.Fatal("committed migration resume failed", err)
		}
		if _, err = a.DB.GetRecord(ctx, "servers", "encrypted"); err != nil {
			t.Fatal("original SQLite was removed")
		}
		if _, err = dst.DB().Exec("UPDATE users SET username='modified'"); err != nil {
			t.Fatal(err)
		}
		if _, err = copyDatabaseManifest(ctx, dst.DB(), *active, manifest); err == nil {
			t.Fatal("target corruption went undetected")
		}
	})
	t.Run("refuse_nonempty_target", func(t *testing.T) {
		target := migrationPostgres(t)
		a, h, token := controllerFixture(t)
		db, err := sql.Open("pgx", target.DSN())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err = db.Exec("CREATE TABLE keep_data (value TEXT); INSERT INTO keep_data VALUES ('keep')"); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/database/migrate", token, map[string]any{"confirm": "迁移到 PostgreSQL", "target": target}), 409)
		var value string
		if err = db.QueryRow("SELECT value FROM keep_data").Scan(&value); err != nil || value != "keep" {
			t.Fatal("target changed")
		}
		if _, err = os.Stat(filepath.Join(a.Config.DataDir, config.DatabasePendingFile)); !os.IsNotExist(err) {
			t.Fatal("migration was queued")
		}
	})
	t.Run("transaction_rolls_back", func(t *testing.T) {
		target := migrationPostgres(t)
		a, _, _ := controllerFixture(t)
		ctx := context.Background()
		backup, err := a.createBackup(ctx, store.User{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(a.Config.DataDir, "backups", text(backup, "id")+".zip"))
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := migrationManifest(raw)
		if err != nil {
			t.Fatal(err)
		}
		users := manifest.Tables["users"]
		users.Rows = append(users.Rows, users.Rows[0])
		manifest.Tables["users"] = users
		db, err := sql.Open("pgx", target.DSN())
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if _, err = copyDatabaseManifest(ctx, db, config.DatabaseChange{ID: "rollback", CreatedAt: time.Now()}, manifest); err == nil {
			t.Fatal("duplicate rows accepted")
		}
		var count int
		if err = db.QueryRow("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema()").Scan(&count); err != nil || count != 0 {
			t.Fatal("failed transaction left tables", count, err)
		}
	})
}

func TestMigrationFailureRetainsSQLite(t *testing.T) {
	a, _, _ := controllerFixture(t)
	pending := config.DatabaseChange{ID: "changed-source", State: "pending", Source: "different", Target: config.PostgreSQL{Host: "127.0.0.1", Port: 1, Database: "unused", Username: "unused", Password: "secret", SSLMode: "disable", MaxOpen: 1}}
	if err := config.WriteDatabaseChange(a.Config.DataDir, config.DatabasePendingFile, pending); err != nil {
		t.Fatal(err)
	}
	switched, err := a.ApplyDatabaseMigration(context.Background())
	if err != nil || switched {
		t.Fatal("unsafe source change accepted")
	}
	change, err := config.ReadDatabaseChange(a.Config.DataDir, config.DatabasePendingFile)
	if err != nil || change.State != "failed" {
		t.Fatal("failure not recorded")
	}
	if _, err = a.DB.UserByUsername(context.Background(), "test-admin"); err != nil {
		t.Fatal("original DB unavailable")
	}
	public, _ := json.Marshal(change.Target.Public())
	if strings.Contains(fmt.Sprint(string(public)), "secret") {
		t.Fatal("password leaked")
	}
}
