package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentRequestsPublishOnlyOneCompleteVersion(t *testing.T) {
	c := &Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Request(context.Background(), "v1.0.2") == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent requests", accepted.Load())
	}
	b, err := os.ReadFile(filepath.Join(c.DataDir, "update-request.json"))
	var row map[string]string
	if err != nil || json.Unmarshal(b, &row) != nil || row["version"] != "v1.0.2" || len(row) != 2 {
		t.Fatalf("partial or excessive request: %s, %v", b, err)
	}
	if s := c.Status(context.Background()); s.Phase != "queued" {
		t.Fatal(s)
	}
	entries, _ := os.ReadDir(c.DataDir)
	if len(entries) != 1 {
		t.Fatal("temporary files leaked")
	}
}

func TestRejectsUnsupportedUnsafeAndActiveUpdates(t *testing.T) {
	c := &Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return errors.New("not installed") }}
	if c.Request(context.Background(), "v1.0.2") == nil {
		t.Fatal("accepted unsupported installation")
	}
	c.Ready = func(context.Context) error { return nil }
	for _, v := range []string{"latest", "v1.2", "../v1.0.2", "v1.0.2;id", "v1.0.2+metadata"} {
		if c.Request(context.Background(), v) == nil {
			t.Fatal(v)
		}
	}
	if err := os.WriteFile(filepath.Join(c.StateDir, "status.json"), []byte(`{"phase":"updating","version":"v1.0.2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if c.Request(context.Background(), "v1.0.3") == nil {
		t.Fatal("accepted while root worker active")
	}
}
