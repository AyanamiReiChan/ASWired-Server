package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestTaskClaimCASAcrossConnections(t *testing.T) {
	s, path := testStore(t)
	second, e := Open(Config{Driver: "sqlite", DSN: path})
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	ctx := context.Background()
	queued, e := s.SaveTask(ctx, Task{ID: "claim", Kind: "core.status", Status: "queued"})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := s
			if i%2 == 1 {
				db = second
			}
			copy := queued
			copy.Status = "running"
			_, err := db.SaveTask(ctx, copy)
			if err == nil {
				won.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("claimed %d times", won.Load())
	}
	running, _ := s.GetTask(ctx, "claim")
	duplicate := running
	running.Status = "success"
	running.Result = json.RawMessage(`{"ok":true}`)
	if _, e = s.SaveTask(ctx, running); e != nil {
		t.Fatal(e)
	}
	duplicate.Status = "failed"
	if _, e = s.SaveTask(ctx, duplicate); !errors.Is(e, ErrConflict) {
		t.Fatal("stale result accepted", e)
	}
	if _, e = s.SaveTask(ctx, Task{ID: "claim", Kind: "core.status", Status: "queued"}); !errors.Is(e, ErrConflict) {
		t.Fatal("new task overwrote old result", e)
	}
}

func TestPendingTasksCannotBeHiddenByCompletedHistory(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	if _, e := s.SaveTask(ctx, Task{ID: "old", ServerID: "node", Kind: "status", Status: "queued"}); e != nil {
		t.Fatal(e)
	}
	for i := range 35 {
		if _, e := s.SaveTask(ctx, Task{ID: fmt.Sprint(i), ServerID: "node", Kind: "status", Status: "success"}); e != nil {
			t.Fatal(e)
		}
	}
	pending, e := s.ListPendingTasks(ctx, "node", 1)
	if e != nil || len(pending) != 1 || pending[0].ID != "old" {
		t.Fatal(pending, e)
	}
	pending[0].Status = "running"
	if _, e = s.SaveTask(ctx, pending[0]); e != nil {
		t.Fatal("pending rows lack CAS state", e)
	}
	running, e := s.ListRunningTasks(ctx, "node", 1)
	if e != nil || len(running) != 1 || running[0].ID != "old" {
		t.Fatal(running, e)
	}
}
func TestTaskAndCredentialBatchAreAtomic(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	r, e := s.SaveRecord(ctx, Record{Collection: "_homeCredentials", ID: "home", Data: map[string]any{"token": "old"}})
	if e != nil {
		t.Fatal(e)
	}
	r.Data["token"] = "new"
	queued := Task{ID: "rotate", Kind: "identity.rotate", Status: "queued", Input: json.RawMessage(`{"token":"new"}`)}
	saved, e := s.CreateTaskWithRecords(ctx, queued, []Record{r})
	if e != nil {
		t.Fatal(e)
	}
	saved.Status = "running"
	if _, e = s.SaveTask(ctx, saved); e != nil {
		t.Fatal("returned task cannot CAS", e)
	}
	current, _ := s.GetRecord(ctx, r.Collection, r.ID)
	current.Data["token"] = "must-rollback"
	if _, e = s.CreateTaskWithRecords(ctx, queued, []Record{current}); !errors.Is(e, ErrConflict) {
		t.Fatal("duplicate task accepted", e)
	}
	current, _ = s.GetRecord(ctx, r.Collection, r.ID)
	if current.Data["token"] != "new" {
		t.Fatal("credentials committed without task")
	}
	queued.ID = "lost"
	if _, e = s.CreateTaskWithRecords(ctx, queued, []Record{r}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale credential accepted", e)
	}
	if _, e = s.GetTask(ctx, "lost"); !errors.Is(e, ErrNotFound) {
		t.Fatal("task committed without credentials")
	}
}
