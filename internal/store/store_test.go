package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.db")
	s, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestInitializeAdminIsAtomicAcrossConnections(t *testing.T) {
	s, path := testStore(t)
	second, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx := context.Background()
	var successes atomic.Int32
	var wg sync.WaitGroup
	const n = 20
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := s
			if i%2 == 1 {
				handle = second
			}
			err := handle.InitializeAdmin(ctx, User{ID: fmt.Sprint(i), Username: fmt.Sprintf("admin-%d", i), PasswordHash: "test-hash", Role: "admin"})
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrInitialized) {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if successes.Load() != 1 {
		t.Fatalf("created %d initial administrators", successes.Load())
	}
	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("users %v %v", users, err)
	}
	if err := s.SetSetting(ctx, "_internal.initialized", false); !errors.Is(err, ErrInvalid) {
		t.Fatal("reserved initialization marker is writable")
	}
}

func TestPersistenceOwnershipAndOptimisticUpdates(t *testing.T) {
	s, path := testStore(t)
	ctx := context.Background()
	if err := s.InitializeAdmin(ctx, User{ID: "admin", Username: "Admin", PasswordHash: "test-hash", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByUsername(ctx, " ADMIN "); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "duplicate", Username: "admin", PasswordHash: "test-hash", Role: "user"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
	r, err := s.SaveRecord(ctx, Record{Collection: "servers", ID: "node-1", OwnerID: "alice", Data: map[string]any{"name": "节点一", "port": 443}})
	if err != nil {
		t.Fatal(err)
	}
	stale := r
	r.Data = map[string]any{"name": "updated"}
	r, err = s.SaveRecord(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	stale.Data = map[string]any{"name": "stale"}
	if _, err := s.SaveRecord(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	other, err := s.ListRecords(ctx, "servers", "bob")
	if err != nil || len(other) != 0 {
		t.Fatal("owner filter exposed another user's record")
	}
	if err := s.SetSetting(ctx, "site", map[string]any{"name": "ASWired"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetRecord(ctx, "servers", "node-1")
	if err != nil || got.Data["name"] != "updated" || got.Version != 2 {
		t.Fatalf("restart lost record: %+v %v", got, err)
	}
	var setting map[string]any
	if err := reopened.GetSetting(ctx, "site", &setting); err != nil || setting["name"] != "ASWired" {
		t.Fatal("restart lost setting")
	}
	u, err := reopened.UserByID(ctx, "admin")
	if err != nil || u.PasswordHash != "test-hash" {
		t.Fatal("restart lost account")
	}
	encoded, _ := json.Marshal(u)
	var public map[string]any
	json.Unmarshal(encoded, &public)
	if _, ok := public["PasswordHash"]; ok {
		t.Fatal("password hash exposed")
	}
	if _, ok := public["passwordHash"]; ok {
		t.Fatal("password hash exposed")
	}
}

func TestTaskResultsMetricsAndAudit(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	task, err := s.SaveTask(ctx, Task{ID: "task-1", ServerID: "node-1", ActorID: "admin", Kind: "xray.status", Status: "pending", Input: json.RawMessage(`{"detail":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(task.Result) != 0 {
		t.Fatal("pending task must not have an invented result")
	}
	task.Status = "succeeded"
	task.Result = json.RawMessage(`{"running":true}`)
	saved, err := s.SaveTask(ctx, task)
	if err != nil || saved.Status != "succeeded" || string(saved.Result) != `{"running":true}` {
		t.Fatalf("task result %v %v", saved, err)
	}
	now := time.Now().UTC()
	m := Metric{ID: "metric-1", ServerID: "node-1", RecordedAt: now, Values: map[string]any{"cpu": 12.5}}
	if err := s.AddMetric(ctx, m); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMetric(ctx, m); err != nil {
		t.Fatal(err)
	}
	metrics, err := s.ListMetrics(ctx, "node-1", now.Add(-time.Minute), 10)
	if err != nil || len(metrics) != 1 {
		t.Fatalf("metric deduplication %v %v", metrics, err)
	}
	if err := s.AppendAudit(ctx, AuditEvent{ID: "audit-1", ActorID: "admin", Action: "xray.status", Target: "node-1"}); err != nil {
		t.Fatal(err)
	}
	audit, err := s.ListAudit(ctx, 10)
	if err != nil || len(audit) != 1 {
		t.Fatalf("audit %v %v", audit, err)
	}
}

func TestAuthenticationChangesCannotRestoreRevokedTokens(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if err := s.InitializeAdmin(ctx, User{ID: "admin", Username: "admin", PasswordHash: "initial-hash", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByID(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	stale := u
	u.TokenVersion++
	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	stale.Username = "new-name"
	if err := s.UpdateUser(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale account update accepted: %v", err)
	}
	u, err = s.UserByID(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	u.PasswordHash = "changed-hash"
	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u, err = s.UserByID(ctx, "admin")
	if err != nil || u.TokenVersion != 2 {
		t.Fatalf("password update failed to revoke token: %+v %v", u, err)
	}
	u.TokenVersion = 0
	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u, err = s.UserByID(ctx, "admin")
	if err != nil || u.TokenVersion != 2 {
		t.Fatal("token version decreased")
	}
}

func TestOnePackageBindingPerUserIsAtomic(t *testing.T) {
	s, path := testStore(t)
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	var success atomic.Int32
	failures := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := s
			if i%2 == 1 {
				handle = other
			}
			_, err := handle.SaveRecord(ctx, Record{Collection: "subscriptions", ID: fmt.Sprintf("sub-%d", i), OwnerID: "member-1", Data: map[string]any{"planId": "plan-1", "name": "binding"}})
			if err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				failures <- err
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if success.Load() != 1 {
		t.Fatalf("concurrent duplicate bindings: %d", success.Load())
	}
	rows, err := s.ListRecords(ctx, "subscriptions", "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v %v", rows, err)
	}
	if err := s.DeleteRecord(ctx, "subscriptions", rows[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRecord(ctx, Record{Collection: "subscriptions", ID: "replacement", OwnerID: "member-1", Data: map[string]any{"planId": "plan-1"}}); err != nil {
		t.Fatalf("deleted binding remains reserved: %v", err)
	}
}
