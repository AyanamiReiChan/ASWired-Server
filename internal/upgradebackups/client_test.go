package upgradebackups

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) *Client {
	t.Helper()
	return &Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
}

func saveState(t *testing.T, c *Client, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.StateDir, StatusFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func listed(id string, deletable bool) Status {
	return Status{Phase: "completed", Items: []Item{{ID: id, CreatedAt: "2026-09-24T12:00:00Z", PreviousVersion: "v1.0.8", SizeBytes: 12, Files: []File{{Name: "controller.tar.gz", SizeBytes: 12}}, Deletable: deletable}}, TotalSizeBytes: 12}
}

func TestConcurrentRequestsPublishOneCompleteFixedRequest(t *testing.T) {
	c := fixture(t)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 12 {
		wg.Go(func() {
			if _, err := c.Request(context.Background(), "list", ""); err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrBusy) {
				t.Errorf("unexpected concurrent error: %v", err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent requests", accepted.Load())
	}
	raw, err := os.ReadFile(filepath.Join(c.DataDir, RequestFile))
	var request Request
	var fields map[string]any
	if err != nil || json.Unmarshal(raw, &request) != nil || !validRequest(request) || json.Unmarshal(raw, &fields) != nil || len(fields) != 4 || request.Operation != "list" || request.BackupID != "" {
		t.Fatalf("incomplete or excessive request: %s, %v", raw, err)
	}
	if status := c.Status(context.Background()); !status.Supported || status.Phase != "queued" || status.RequestID != request.ID {
		t.Fatal("queued state missing", status)
	}
	entries, err := os.ReadDir(c.DataDir)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary request files leaked", entries, err)
	}
	// Worker retains the request until after publishing its final status.
	for _, phase := range []string{"scanning", "completed", "failed"} {
		saveState(t, c, Status{Phase: phase, RequestID: request.ID, Operation: "list", Items: []Item{}})
		if status := c.Status(context.Background()); status.Phase != phase {
			t.Fatal("pending request masked matching worker phase", status)
		}
		if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrBusy) {
			t.Fatal("request was replaced before worker cleanup", err)
		}
	}
}

func TestRejectsInvalidUnreviewedProtectedUnsupportedAndUpgradingRequests(t *testing.T) {
	c := fixture(t)
	for _, id := range []string{"", "../20260924T120000Z", "20260924T120000Z/..", "20260230T120000Z", "20260924T250000Z", "20260924t120000z", "20260924T120000Z\n", "20260924T120000Z;id"} {
		if _, err := c.Request(context.Background(), "delete", id); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted unsafe id %q: %v", id, err)
		}
	}
	for _, operation := range []string{"refresh", "rm", "", "list;id"} {
		if _, err := c.Request(context.Background(), operation, ""); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted unknown operation", operation, err)
		}
	}
	id := "20260924T120000Z"
	if _, err := c.Request(context.Background(), "delete", id); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted without a reviewed list entry", err)
	}
	saveState(t, c, listed(id, false))
	if _, err := c.Request(context.Background(), "delete", id); !errors.Is(err, ErrProtected) {
		t.Fatal("accepted protected backup", err)
	}
	c.Ready = func(context.Context) error { return errors.New("old install") }
	if status := c.Status(context.Background()); status.Supported || len(status.Items) != 1 || status.Reason != "old install" {
		t.Fatal("unsupported installation lost its typed summary", status)
	}
	if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("accepted unsupported installation", err)
	}
	c.Ready = func(context.Context) error { return nil }
	for _, phase := range []string{"queued", "updating"} {
		if err := os.WriteFile(filepath.Join(c.StateDir, "status.json"), []byte(`{"phase":"`+phase+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrBusy) {
			t.Fatal("accepted during an upgrade", phase, err)
		}
	}
	if err := os.Remove(filepath.Join(c.StateDir, "status.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.DataDir, "update-request.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrBusy) {
		t.Fatal("accepted during queued upgrade", err)
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected request was published", err)
	}
}

func TestTypedBoundedStatusRetainsFailureAndRejectsUnsafeSummaries(t *testing.T) {
	c := fixture(t)
	id := "20260924T120000Z"
	state := listed(id, true)
	state.Phase, state.Operation, state.Message = "failed", "list", "scan failed"
	state.Truncated, state.RemainingCount = true, 2
	raw, _ := json.Marshal(state)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	object["privateKey"], object["archivePath"], object["supported"], object["reason"] = "secret-marker", "/root/secret-marker", false, "secret-marker"
	saveState(t, c, object)
	status := c.Status(context.Background())
	encoded, _ := json.Marshal(status)
	if !status.Supported || status.Phase != "failed" || len(status.Items) != 1 || !status.Truncated || status.RemainingCount != 2 || strings.Contains(string(encoded), "secret-marker") {
		t.Fatal("typed status contract violated", string(encoded))
	}
	for _, corrupt := range []any{
		map[string]any{"phase": "deleting", "requestId": "../unsafe"},
		map[string]any{"phase": "unknown"},
		map[string]any{"phase": "completed", "items": []Item{{ID: id, CreatedAt: "2026-09-24T12:00:00Z", Files: []File{{Name: "../secret", SizeBytes: 1}}}}},
		map[string]any{"phase": "completed", "items": []Item{{ID: id, CreatedAt: "not-a-date"}}},
		map[string]any{"phase": "completed", "items": make([]Item, MaxItems+1)},
		map[string]any{"phase": "completed", "items": []Item{state.Items[0], state.Items[0]}, "totalSizeBytes": 24},
		map[string]any{"phase": "completed", "totalSizeBytes": 100},
	} {
		saveState(t, c, corrupt)
		if status := c.Status(context.Background()); status.Phase != "failed" || len(status.Items) != 0 {
			t.Fatal("accepted invalid summary", status)
		}
		if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrState) {
			t.Fatal("requested over unreadable worker state", err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.StateDir, StatusFile), []byte(strings.Repeat(" ", MaxStatusBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if status := c.Status(context.Background()); status.Phase != "failed" || len(status.Items) != 0 {
		t.Fatal("oversized summary accepted", status)
	}
}

func TestDeletePublishesOnlyIDWithoutOpeningArchives(t *testing.T) {
	c := fixture(t)
	id := "20260924T120000Z"
	saveState(t, c, listed(id, true))
	request, err := c.Request(context.Background(), "delete", id)
	if err != nil || !validRequest(request) || request.BackupID != id {
		t.Fatal(request, err)
	}
	if status := c.Status(context.Background()); status.Operation != "delete" || status.BackupID != id || len(status.Items) != 1 {
		t.Fatal(status)
	}
	// No root-owned archive tree exists in this fixture. Queueing works solely
	// through the worker summary, without creating or reading archive paths.
	entries, _ := os.ReadDir(c.DataDir)
	if len(entries) != 1 || entries[0].Name() != RequestFile {
		t.Fatal("client accessed unexpected paths", entries)
	}
}

func TestLargeValidSummaryAndInvalidPendingRequest(t *testing.T) {
	c := fixture(t)
	status := Status{Phase: "completed", Items: []Item{}}
	for i := range MaxItems {
		at := time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		status.Items = append(status.Items, Item{ID: at.Format("20060102T150405Z"), CreatedAt: at.Format(time.RFC3339), PreviousVersion: "v1.0.8", Files: []File{{Name: "data.tar.gz"}}, Deletable: true})
	}
	saveState(t, c, status)
	if got := c.Status(context.Background()); len(got.Items) != MaxItems {
		t.Fatal("valid summary over old 8KiB limit was lost", len(got.Items), got.Message)
	}
	if err := os.WriteFile(filepath.Join(c.DataDir, RequestFile), []byte(`{"id":"secret-marker","operation":"delete","backupId":"../../secret-marker"}`), 0600); err != nil {
		t.Fatal(err)
	}
	got := c.Status(context.Background())
	encoded, _ := json.Marshal(got)
	if got.Phase != "failed" || strings.Contains(string(encoded), "secret-marker") {
		t.Fatal("unsafe pending request reflected", string(encoded))
	}
	if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrBusy) {
		t.Fatal("invalid request silently overwritten", err)
	}
}

func TestUnsupportedUnmanagedInstallation(t *testing.T) {
	c := New(t.TempDir())
	if c.Status(context.Background()).Supported {
		t.Fatal("unmanaged install was marked supported")
	}
	if _, err := c.Request(context.Background(), "list", ""); !errors.Is(err, ErrUnsupported) {
		t.Fatal("unmanaged install accepted a request", err)
	}
}

func TestWorkerSummaryContract(t *testing.T) {
	c := fixture(t)
	// This is the root worker's public summary shape, including Python's UTC
	// offset and its fixed backup filenames; no archive contents are exposed.
	raw := `{"phase":"completed","requestId":"0123456789abcdef0123456789abcdef","operation":"list","backupId":"","message":"升级备份列表已刷新","updatedAt":"2026-09-24T01:23:46+00:00","items":[{"id":"20260924T012345Z","createdAt":"2026-09-24T01:23:45+00:00","previousVersion":"v1.0.8","sizeBytes":100,"files":[{"name":"data.tar.gz","sizeBytes":50},{"name":"config.tar.gz","sizeBytes":20},{"name":"previous-release","sizeBytes":20},{"name":"postgres-backup","sizeBytes":10}],"deletable":true}],"totalSizeBytes":100,"truncated":false,"remainingCount":0}`
	if err := os.WriteFile(filepath.Join(c.StateDir, StatusFile), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	status := c.Status(context.Background())
	if status.Phase != "completed" || !status.Supported || len(status.Items) != 1 || len(status.Items[0].Files) != 4 || status.TotalSizeBytes != 100 {
		t.Fatal("root worker summary rejected", status)
	}
	// The worker uses this diagnostic form when an invalid request has no
	// safely validated ID, and locks cached entries against deletion.
	status.Phase, status.RequestID, status.Message = "failed", "", "升级正在进行，暂时不能删除"
	status.Items[0].Deletable = false
	status.Items[0].Reason = status.Message
	saveState(t, c, status)
	if got := c.Status(context.Background()); got.Phase != "failed" || len(got.Items) != 1 || got.Items[0].Deletable || got.RequestID != "" {
		t.Fatal("root worker failure was not retained", got)
	}
}
