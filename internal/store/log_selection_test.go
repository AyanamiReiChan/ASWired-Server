package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func selectionTask(t *testing.T, s *Store, id, status, kind string, created, updated time.Time) Task {
	t.Helper()
	ctx := context.Background()
	task, err := s.SaveTask(ctx, Task{ID: id, Kind: kind, Status: status, CreatedAt: created, Input: json.RawMessage(`{"keep":"input"}`), Result: json.RawMessage(`{"keep":"result"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().ExecContext(ctx, s.Bind(`UPDATE tasks SET updated_at=? WHERE id=?`), stamp(updated), id); err != nil {
		t.Fatal(err)
	}
	task, err = s.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestLogSelectionProtectsActiveConsumersAndIncludesWholeRange(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	from := time.Date(2026, 9, 16, 16, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	now := to.Add(-time.Hour)
	for i, status := range []string{"success", "failed", "unsupported", "superseded"} {
		selectionTask(t, s, fmt.Sprint("done-", i), status, "core.status", from.Add(time.Duration(i)), now)
	}
	for _, status := range []string{"queued", "running", "unknown"} {
		selectionTask(t, s, status, status, "core.status", from, now)
	}
	selectionTask(t, s, "last-nanosecond", "success", "core.status", to.Add(-time.Nanosecond), now)
	selectionTask(t, s, "chain", "success", "network.forward.apply", from, now)
	selectionTask(t, s, "short", "success", "source.fetch", from, now)
	selectionTask(t, s, "before", "success", "core.status", from.Add(-time.Nanosecond), now)
	selectionTask(t, s, "after", "success", "core.status", to, now)
	if _, err := s.SaveRecord(ctx, Record{Collection: "_forwardChains", ID: "chain-state", Data: map[string]any{"status": "waiting", "currentTaskId": "chain"}}); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewLogSelection(ctx, "tasks", from, to, now)
	if err != nil || preview.Total != 10 || preview.Deletable != 5 || preview.Protected != 5 {
		t.Fatalf("invalid preview: %+v %v", preview, err)
	}
	deleted, err := s.DeleteLogSelection(ctx, "tasks", from, to, now, preview.Fingerprint, nil)
	if err != nil || deleted != preview {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	for _, id := range []string{"queued", "running", "unknown", "chain", "short", "before", "after"} {
		task, err := s.GetTask(ctx, id)
		if err != nil || task.LogsDeleted || len(task.Result) == 0 {
			t.Fatalf("protected task changed: %s %v", id, err)
		}
	}
	for _, id := range []string{"done-0", "done-1", "done-2", "done-3", "last-nanosecond"} {
		task, err := s.GetTask(ctx, id)
		if err != nil || !task.LogsDeleted || len(task.Input) != 0 || len(task.Result) != 0 {
			t.Fatalf("log not cleared: %s %v", id, err)
		}
	}
}

func TestLogSelectionRejectsChangedPreviewWithoutPartialDeletion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	from := time.Now().UTC().Add(-time.Hour)
	to := from.Add(2 * time.Hour)
	now := from.Add(time.Hour)
	selectionTask(t, s, "first", "success", "core.status", from, now)
	pending := selectionTask(t, s, "pending", "running", "core.status", from, now)
	short := selectionTask(t, s, "short", "success", "source.fetch", from, now)
	preview, err := s.PreviewLogSelection(ctx, "tasks", from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	selectionTask(t, s, "arrived", "success", "core.status", from, now)
	if _, err = s.DeleteLogSelection(ctx, "tasks", from, to, now, preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("new log was not rejected: %v", err)
	}
	preview, err = s.PreviewLogSelection(ctx, "tasks", from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	pending.Status = "success"
	if _, err = s.SaveTask(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteLogSelection(ctx, "tasks", from, to, now, preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("status change was not rejected: %v", err)
	}
	preview, err = s.PreviewLogSelection(ctx, "tasks", from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteLogSelection(ctx, "tasks", from, to, short.UpdatedAt.Add(time.Minute), preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("newly deletable task not rejected: %v", err)
	}
	preview, err = s.PreviewLogSelection(ctx, "tasks", from, to, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveRecord(ctx, Record{Collection: "_forwardChains", ID: "new-chain", Data: map[string]any{"status": "waiting", "currentTaskId": "first"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteLogSelection(ctx, "tasks", from, to, now, preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("dependency change was not rejected: %v", err)
	}
	for _, id := range []string{"first", "pending", "short", "arrived"} {
		task, err := s.GetTask(ctx, id)
		if err != nil || task.LogsDeleted || len(task.Result) == 0 {
			t.Fatalf("failed confirmation partially deleted %s: %v", id, err)
		}
	}
}

func seedSelectionAudits(t *testing.T, s *Store, count int, created time.Time) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, s.Bind(`INSERT INTO audit_events(id,actor_id,action,target,details,created_at) VALUES(?,'actor','test','target','{}',?)`))
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close()
	for i := 0; i < count; i++ {
		if _, err = statement.ExecContext(ctx, fmt.Sprintf("audit-%05d", i), stamp(created)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestLogSelectionProcessesBeyondListPageAndRejectsOverLimit(t *testing.T) {
	for _, count := range []int{1205, MaxLogSelection + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			from := time.Now().Add(-time.Hour)
			to := from.Add(2 * time.Hour)
			seedSelectionAudits(t, s, count, from)
			preview, err := s.PreviewLogSelection(ctx, "audit", from, to, time.Now())
			if count > MaxLogSelection {
				if !errors.Is(err, ErrLogSelectionTooLarge) {
					t.Fatalf("large selection silently truncated: %v", err)
				}
				if _, err = s.DeleteLogSelection(ctx, "audit", from, to, time.Now(), "", nil); !errors.Is(err, ErrLogSelectionTooLarge) {
					t.Fatalf("large delete not blocked: %v", err)
				}
				var actual int
				if err = s.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&actual); err != nil || actual != count {
					t.Fatal("oversized selection changed data")
				}
				return
			}
			if err != nil || preview.Total != count || preview.Deletable != count {
				t.Fatalf("preview truncated: %+v %v", preview, err)
			}
			if _, err = s.DeleteLogSelection(ctx, "audit", from, to, time.Now(), preview.Fingerprint, nil); err != nil {
				t.Fatal(err)
			}
			var remaining int
			if err = s.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatal("multi-page delete incomplete")
			}
		})
	}
}

func TestLogSelectionTransactionRollsBackEarlierDeletesOnFailure(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	from := time.Now().Add(-time.Hour)
	to := from.Add(2 * time.Hour)
	for _, id := range []string{"a", "b"} {
		selectionTask(t, s, id, "success", "core.status", from, time.Now())
	}
	preview, err := s.PreviewLogSelection(ctx, "tasks", from, to, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB().Exec(`CREATE TRIGGER fail_second_log BEFORE INSERT ON records WHEN NEW.collection='_deletedTaskLogs' AND NEW.id='b' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteLogSelection(ctx, "tasks", from, to, time.Now(), preview.Fingerprint, nil); err == nil {
		t.Fatal("injected write failure ignored")
	}
	for _, id := range []string{"a", "b"} {
		task, err := s.GetTask(ctx, id)
		if err != nil || task.LogsDeleted || len(task.Input) == 0 || len(task.Result) == 0 {
			t.Fatalf("partial delete committed: %s %v", id, err)
		}
	}
}

func TestLogSelectionFingerprintIncludesFullMembershipAndScope(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	from := time.Now().Add(-time.Hour)
	to := from.Add(2 * time.Hour)
	for _, id := range []string{"a", "b"} {
		if err := s.AppendAudit(ctx, AuditEvent{ID: id, Action: "test", CreatedAt: from}); err != nil {
			t.Fatal(err)
		}
	}
	preview, err := s.PreviewLogSelection(ctx, "audit", from, to, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteAudit(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteLogSelection(ctx, "audit", from, to, time.Now(), preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("removed record did not invalidate preview: %v", err)
	}
	var count int
	if err = s.DB().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id='a'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("remaining unconfirmed log deleted")
	}
	preview, err = s.PreviewLogSelection(ctx, "audit", to, to.Add(time.Hour), time.Now())
	if err != nil || preview.Total != 0 {
		t.Fatal("empty fixture failed")
	}
	if _, err = s.DeleteLogSelection(ctx, "tasks", to, to.Add(time.Hour), time.Now(), preview.Fingerprint, nil); !errors.Is(err, ErrLogPreviewChanged) {
		t.Fatalf("cross-collection fingerprint accepted: %v", err)
	}
}
