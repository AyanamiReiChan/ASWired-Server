package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestXrayCacheSyncPersistenceAndAuthorization(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "cache-server", Data: map[string]any{"name": "Cache server"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a.syncXrayCache(ctx, "cache-server", now)
	a.syncXrayCache(ctx, "cache-server", now.Add(time.Second))
	tasks, err := a.DB.ListPendingTasks(ctx, "cache-server", 100)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("poll duplicated: %d %v", len(tasks), err)
	}
	task := tasks[0]
	task.Status = "running"
	_, err = a.DB.SaveTask(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	if !a.finishTask(ctx, "cache-server", agentwire.Result{ID: task.ID, Status: "success", Data: map[string]any{"config": map[string]any{"privateKey": "cached-private"}}}) {
		t.Fatal("result rejected")
	}
	before, _ := a.DB.GetRecord(ctx, "_xrayCache", "cache-server")
	if before.Data["config"] == nil || before.Data["syncedAt"] == nil {
		t.Fatal("cache not persisted")
	}
	for i := 0; i < 3; i++ {
		response := controllerRequest(t, h, "GET", "/api/servers/cache-server/xray-cache", token, nil)
		requireStatus(t, response, http.StatusOK)
		if !strings.Contains(response.Body.String(), "cached-private") || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing private snapshot or no-store")
		}
	}
	tasks, _ = a.DB.ListPendingTasks(ctx, "cache-server", 100)
	if len(tasks) != 0 {
		t.Fatal("cache reads queued Agent calls")
	}
	a.syncXrayCache(ctx, "cache-server", now.Add(time.Minute))
	tasks, _ = a.DB.ListPendingTasks(ctx, "cache-server", 100)
	if len(tasks) != 0 {
		t.Fatal("polled too early")
	}
	a.syncXrayCache(ctx, "cache-server", now.Add(6*time.Minute))
	tasks, _ = a.DB.ListPendingTasks(ctx, "cache-server", 100)
	if len(tasks) != 1 {
		t.Fatal("periodic sync not queued")
	}
	// Failed reads preserve last known configuration.
	failed := tasks[0]
	failed.Status = "running"
	_, _ = a.DB.SaveTask(ctx, failed)
	a.finishTask(ctx, "cache-server", agentwire.Result{ID: failed.ID, Status: "failed", Error: "offline"})
	after, _ := a.DB.GetRecord(ctx, "_xrayCache", "cache-server")
	if after.Data["syncedAt"] != before.Data["syncedAt"] || after.Data["config"] == nil || after.Data["lastError"] == nil {
		t.Fatal("failed sync erased snapshot")
	}
	member := store.User{ID: "cache-user", Username: "cache-user", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err = a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/cache-server/xray-cache", memberToken, nil), http.StatusForbidden)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/missing/xray-cache", token, nil), http.StatusNotFound)
	state := controllerRequest(t, h, "GET", "/api/state", token, nil)
	if strings.Contains(state.Body.String(), "cached-private") {
		t.Fatal("cache leaked to workspace")
	}
	history, _ := a.DB.ListRecords(ctx, "_configHistory", "")
	if len(history) != 0 {
		t.Fatal("periodic polls created unbounded history")
	}
}

func TestXrayCacheIgnoresLateReadsAfterApply(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.get", ServerID: "s", CreatedAt: now.Add(-time.Minute), UpdatedAt: now}, agentwire.Result{Status: "success", Data: map[string]any{"config": map[string]any{"tag": "before"}}})
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.apply", ServerID: "s", UpdatedAt: now.Add(time.Second)}, agentwire.Result{Status: "success"})
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.get", ServerID: "s", CreatedAt: now, UpdatedAt: now.Add(2 * time.Second)}, agentwire.Result{Status: "success", Data: map[string]any{"config": map[string]any{"tag": "stale"}}})
	cache, _ := a.DB.GetRecord(ctx, "_xrayCache", "s")
	if cache.Data["syncedAt"] != nil || cache.Data["invalidatedAt"] == nil || cache.Data["config"].(map[string]any)["tag"] != "before" {
		t.Fatal("late result replaced invalidated snapshot")
	}
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.get", ServerID: "s", CreatedAt: now.Add(3 * time.Second), UpdatedAt: now.Add(4 * time.Second)}, agentwire.Result{Status: "success", Data: map[string]any{"config": map[string]any{"tag": "after"}}})
	cache, _ = a.DB.GetRecord(ctx, "_xrayCache", "s")
	if cache.Data["invalidatedAt"] != nil || cache.Data["config"].(map[string]any)["tag"] != "after" {
		t.Fatal("new snapshot not accepted")
	}
}

func TestXrayCacheWaitsForRunningConfigTask(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_, err := a.DB.SaveTask(ctx, store.Task{ID: "already-reading", ServerID: "s", Kind: "core.config.get", Status: "running", CreatedAt: now, UpdatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	a.syncXrayCache(ctx, "s", now)
	queued, err := a.DB.ListPendingTasks(ctx, "s", 100)
	if err != nil || len(queued) != 0 {
		t.Fatal("queued duplicate while a manual read was running")
	}
}

func TestXrayCacheHashChangesRetriesAndRestart(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observe := func(hash string) {
		t.Helper()
		old, _ := a.DB.GetRecord(ctx, "_observations", "hashed")
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: "hashed", Version: old.Version, Data: map[string]any{"core": map[string]any{"config_sha256": hash}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(at time.Time, count int) []store.Task {
		t.Helper()
		a.syncXrayCache(ctx, "hashed", at)
		tasks, err := a.DB.ListPendingTasks(ctx, "hashed", 100)
		if err != nil || len(tasks) != count {
			t.Fatalf("wanted %d polls, got %d: %v", count, len(tasks), err)
		}
		return tasks
	}
	finish := func(task store.Task, status, hash string) {
		t.Helper()
		task.Status = "running"
		if _, err := a.DB.SaveTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		if !a.finishTask(ctx, "hashed", agentwire.Result{ID: task.ID, Status: status, Data: map[string]any{"config": map[string]any{"tag": hash}, "sha256": hash}}) {
			t.Fatal("result rejected")
		}
	}
	observe(hashA)
	task := check(now, 1)[0]
	check(now.Add(time.Second), 1) // no duplicate while queued
	finish(task, "success", hashA)
	check(now.Add(24*time.Hour), 0)
	// Hash and snapshot are persisted, so a fresh controller does not refetch.
	restarted := &App{DB: a.DB}
	restarted.syncXrayCache(ctx, "hashed", now.Add(30*24*time.Hour))
	if tasks, _ := a.DB.ListPendingTasks(ctx, "hashed", 100); len(tasks) != 0 {
		t.Fatal("restart forgot cached hash")
	}
	observe(hashB)
	task = check(now.Add(2*time.Second), 1)[0] // bypass the five-minute delay
	finish(task, "failed", hashB)
	check(now.Add(3*time.Second), 0)
	cache, _ := a.DB.GetRecord(ctx, "_xrayCache", "hashed")
	if text(cache.Data, "sha256") != hashA || cache.Data["config"] == nil {
		t.Fatal("failure replaced the cached snapshot/hash")
	}
	task = check(now.Add(6*time.Minute), 1)[0]
	finish(task, "success", hashB)
	check(now.Add(24*time.Hour), 0)
	// Apply/restore invalidates even when the reported hash has not changed yet.
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.apply", ServerID: "hashed", UpdatedAt: now.Add(7 * time.Minute)}, agentwire.Result{Status: "success"})
	check(now.Add(7*time.Minute+time.Second), 1)
}

func TestXrayCacheBootstrapsLegacySnapshotHash(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	a.finishXrayCache(ctx, store.Task{Kind: "core.config.get", ServerID: "legacy", CreatedAt: now, UpdatedAt: now}, agentwire.Result{Status: "success", Data: map[string]any{"config": map[string]any{}}})
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: "legacy", Data: map[string]any{"core": map[string]any{"config_sha256": strings.Repeat("c", 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	a.syncXrayCache(ctx, "legacy", now.Add(time.Second))
	tasks, _ := a.DB.ListPendingTasks(ctx, "legacy", 100)
	if len(tasks) != 1 {
		t.Fatal("missing hash was not refreshed")
	}
}
