package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTaskLogDeletionKeepsOnlyImmutableOutcome(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	task, err := s.SaveTask(ctx, Task{ID: "done", ServerID: "server", ActorID: "actor", Kind: "core.policy.apply", Status: "success", Input: json.RawMessage(`{"secret":"input"}`), Result: json.RawMessage(`{"secret":"output"}`), Error: "private detail"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTaskLog(ctx, task, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	kept, err := s.GetTask(ctx, task.ID)
	if err != nil || !kept.LogsDeleted || kept.Status != "success" || kept.ServerID != "server" || kept.Kind != task.Kind || !kept.UpdatedAt.Equal(task.UpdatedAt) || len(kept.Input) != 0 || len(kept.Result) != 0 || kept.Error != "" {
		t.Fatalf("invalid outcome: %+v %v", kept, err)
	}
	if _, err = s.SaveTask(ctx, task); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale result restored log: %v", err)
	}
	if _, err = s.SaveTask(ctx, kept); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted outcome modified: %v", err)
	}
	exists, err := s.HasOtherTask(ctx, "server", "core.policy.apply", "")
	if err != nil || !exists {
		t.Fatal("policy history was erased")
	}
	for _, id := range []string{"recent-a", "recent-b"} {
		if _, err = s.SaveTask(ctx, Task{ID: id, Kind: "core.status", Status: "success", CreatedAt: time.Now().Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	logs, err := s.ListTasks(ctx, "", 2)
	if err != nil || len(logs) != 2 || logs[0].ID == "done" || logs[1].ID == "done" {
		t.Fatalf("filtered after limit: %+v %v", logs, err)
	}
}

func TestTaskLogDeletionProtectsActiveAndChangedTasks(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	for _, status := range []string{"queued", "running", "unknown", "future-status"} {
		task, err := s.SaveTask(ctx, Task{ID: status, Kind: "core.status", Status: status, Result: json.RawMessage(`{"retained":true}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.DeleteTaskLog(ctx, task, time.Now(), ""); !errors.Is(err, ErrTaskLogProtected) {
			t.Fatalf("deleted %s: %v", status, err)
		}
	}
	stale, err := s.SaveTask(ctx, Task{ID: "changing", Kind: "core.status", Status: "success", Result: json.RawMessage(`{"retained":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	current := stale
	current.Status = "running"
	if _, err = s.SaveTask(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTaskLog(ctx, stale, time.Now(), ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale snapshot accepted: %v", err)
	}
	current, err = s.GetTask(ctx, stale.ID)
	if err != nil || current.Status != "running" || current.LogsDeleted || len(current.Result) == 0 {
		t.Fatal("live task changed")
	}
}

func TestTaskLogDeletionProtectsConsumersAtomically(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	task, err := s.SaveTask(ctx, Task{ID: "chain-task", Kind: "network.forward.apply", Status: "success", Input: json.RawMessage(`{"input":true}`), Result: json.RawMessage(`{"result":true}`), Error: "retained"})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := s.SaveRecord(ctx, Record{Collection: "_forwardChains", ID: "chain", Data: map[string]any{"status": "waiting", "currentTaskId": task.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTaskLog(ctx, task, time.Now(), ""); !errors.Is(err, ErrTaskLogProtected) {
		t.Fatalf("chain task removed: %v", err)
	}
	kept, err := s.GetTask(ctx, task.ID)
	if err != nil || kept.LogsDeleted || len(kept.Input) == 0 || len(kept.Result) == 0 || kept.Error != "retained" {
		t.Fatal("rollback lost log data")
	}
	chain.Data["status"] = "success"
	if _, err = s.SaveRecord(ctx, chain); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTaskLog(ctx, task, time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"source.fetch", "federation.identity"} {
		task, err := s.SaveTask(ctx, Task{ID: kind, Kind: kind, Status: "success"})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.DeleteTaskLog(ctx, task, task.UpdatedAt.Add(time.Minute-time.Nanosecond), ""); !errors.Is(err, ErrTaskLogProtected) {
			t.Fatalf("short consumer not protected: %v", err)
		}
		if err = s.DeleteTaskLog(ctx, task, task.UpdatedAt.Add(time.Minute), ""); err != nil {
			t.Fatalf("one minute boundary: %v", err)
		}
	}
}
