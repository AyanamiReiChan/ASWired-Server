package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("ASWIRED_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ASWIRED_TEST_POSTGRES_DSN is unset; real PostgreSQL integration not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL test connection settings")
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal("cannot reach PostgreSQL test server")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	schema := "aswired_test_" + hex.EncodeToString(random[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("remove isolated test schema: %v", err)
		}
	}()
	cfg.RuntimeParams["search_path"] = schema
	registered := stdlib.RegisterConnConfig(cfg)
	defer stdlib.UnregisterConnConfig(registered)
	db, err := Open(Config{Driver: "postgres", DSN: registered})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	second, err := Open(Config{Driver: "pgx", DSN: registered})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	t.Run("traffic usage remains uncached", func(t *testing.T) {
		checkUsage(t, db, "usage-test", 10, 20, TrafficUsage{})
		checkNodeUsage(t, db, "usage-test", "email", 10, 20, 0)
		usageExec(t, second.db, second.Bind(insertUsageRow), "usage-test", "usage-test", "uplink", 1.25, 10)
		checkUsage(t, db, "usage-test", 10, 20, TrafficUsage{Total: 1.25, Up: 1.25})
		checkNodeUsage(t, db, "usage-test", "email", 10, 20, 1.25)
		usageExec(t, second.db, `UPDATE traffic_ledger SET direction='downlink',weighted_bytes=2.5 WHERE id='usage-test'`)
		checkUsage(t, db, "usage-test", 10, 20, TrafficUsage{Total: 2.5, Down: 2.5})
		checkNodeUsage(t, db, "usage-test", "email", 10, 20, 2.5)
		checkNodeUsage(t, db, "usage-test", "other-email", 10, 20, 0)
		checkUsage(t, db, "usage-test", 11, 20, TrafficUsage{})
		usageExec(t, second.db, `DELETE FROM traffic_ledger WHERE id='usage-test'`)
		checkUsage(t, db, "usage-test", 10, 20, TrafficUsage{})
		checkNodeUsage(t, db, "usage-test", "email", 10, 20, 0)
	})
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := db
			if i%2 != 0 {
				handle = second
			}
			err := handle.InitializeAdmin(ctx, User{ID: fmt.Sprintf("admin-%d", i), Username: fmt.Sprintf("admin%d", i), PasswordHash: "test-hash", Role: "admin"})
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrInitialized) {
				t.Errorf("concurrent initialize: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("initial admins %d", wins.Load())
	}
	users, err := db.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("read admin %v", err)
	}
	user := users[0]
	user.PasswordHash = "replacement-hash"
	user.TokenVersion = 1 << 54
	if err := db.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	updated, err := db.UserByID(ctx, user.ID)
	if err != nil || updated.TokenVersion != 1<<54 {
		t.Fatalf("BIGINT JWT version failed: %v", err)
	}
	if err := db.SetEncryptionKey([]byte(strings.Repeat("k", 32))); err != nil {
		t.Fatal(err)
	}
	code, err := db.SaveRecord(ctx, Record{Collection: "codes", ID: "one", Data: map[string]any{"state": "unused"}})
	if err != nil {
		t.Fatal(err)
	}
	code.Data["state"] = "consumed"
	sub := Record{Collection: "subscriptions", ID: "sub", OwnerID: user.ID, Data: map[string]any{"planId": "plan", "password": "sensitive"}}
	saved, err := db.CompareAndSaveRecords(ctx, []Record{code, sub})
	if err != nil || len(saved) != 2 {
		t.Fatalf("transactional save %v", err)
	}
	var ciphertext string
	if err := db.DB().QueryRowContext(ctx, db.Bind("SELECT data FROM records WHERE collection=? AND id=?"), "subscriptions", "sub").Scan(&ciphertext); err != nil || strings.Contains(ciphertext, "sensitive") {
		t.Fatal("PostgreSQL secret storage invalid")
	}
	stale := saved[0]
	stale.Version = 1
	candidate := Record{Collection: "nodes", ID: "rolled-back", Data: map[string]any{"name": "unused"}}
	if _, err := db.CompareAndSaveRecords(ctx, []Record{candidate, stale}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS %v", err)
	}
	if _, err := db.GetRecord(ctx, "nodes", "rolled-back"); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial transaction committed")
	}
	task, err := db.SaveTask(ctx, Task{ID: "task", Kind: "core.status", Status: "queued", Input: json.RawMessage(`{"action":"core.status"}`)})
	if err != nil {
		t.Fatal(err)
	}
	task.Status = "success"
	task.Result = json.RawMessage(`{"observed":true}`)
	if _, err := db.SaveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Rollback()
	var before int
	if err := snapshot.QueryRowContext(ctx, "SELECT COUNT(*) FROM records").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SaveRecord(ctx, Record{Collection: "nodes", ID: "later", Data: map[string]any{"name": "later"}}); err != nil {
		t.Fatal(err)
	}
	var after int
	if err := snapshot.QueryRowContext(ctx, "SELECT COUNT(*) FROM records").Scan(&after); err != nil || before != after {
		t.Fatal("repeatable backup snapshot changed")
	}
}
