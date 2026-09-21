package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestConfigurationRemainsReachableBehindUserSyncs(t *testing.T) {
	db, _ := testStore(t)
	ctx := context.Background()
	for i := 0; i < 110; i++ {
		if _, err := db.SaveTask(ctx, Task{ID: fmt.Sprintf("sync-%03d", i), ServerID: "server", Kind: "core.users.sync", Status: "queued"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.SaveTask(ctx, Task{ID: "config", ServerID: "server", Kind: "core.config.apply", Status: "queued"}); err != nil {
		t.Fatal(err)
	}
	tasks, err := db.ListPendingTasks(ctx, "server", 100)
	if err != nil || len(tasks) != 100 || tasks[0].ID != "config" {
		t.Fatalf("configuration blocked: %v %v", tasks, err)
	}
}

func TestTaskDeletionChangesRollbackOnConflict(t *testing.T) {
	db, _ := testStore(t)
	ctx := context.Background()
	first, err := db.SaveRecord(ctx, Record{Collection: "nodes", ID: "first", Data: map[string]any{"name": "first"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.SaveRecord(ctx, Record{Collection: "inbounds", ID: "second", Data: map[string]any{"name": "second"}})
	if err != nil {
		t.Fatal(err)
	}
	stale := second
	second.Data["name"] = "edited"
	second, err = db.SaveRecord(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	task := Task{ID: "deletion", Kind: "core.config.apply", Status: "queued"}
	marker := Record{Collection: "_deletedManagedInbounds", ID: "marker", Data: map[string]any{"taskId": task.ID}}
	if _, err = db.CreateTaskWithChanges(ctx, task, []Record{marker}, []Record{first, stale}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = db.GetRecord(ctx, "nodes", "first"); err != nil {
		t.Fatal("partial deletion", err)
	}
	if _, err = db.GetRecord(ctx, marker.Collection, marker.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial tombstone", err)
	}
	if _, err = db.GetTask(ctx, task.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("orphan command", err)
	}
	if _, err = db.CreateTaskWithChanges(ctx, task, []Record{marker}, []Record{first, second}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetRecord(ctx, "nodes", "first"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = db.GetTask(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
}
