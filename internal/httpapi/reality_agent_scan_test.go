package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"testing"
	"time"
)

func TestAgentRealityResultBinding(t *testing.T) {
	targets, _ := parseRealityScanTargets("example.test")
	server := store.Record{ID: "actual-agent", Data: map[string]any{"name": "Actual Agent"}}
	valid := realityScanResult{ID: "untrusted-id", Target: "example.test:443", Host: "example.test", Port: 443, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), Source: "controller", ServerID: "other-agent"}
	encode := func(results ...realityScanResult) []byte {
		raw, _ := json.Marshal(map[string]any{"results": results})
		return raw
	}
	result, err := decodeAgentRealityResults(encode(valid), targets, server)
	if err != nil {
		t.Fatal(err)
	}
	if result[0].Source != "agent" || result[0].ServerID != server.ID || result[0].ID == valid.ID || result[0].ServerName != "Actual Agent" {
		t.Fatal("untrusted result origin survived", result)
	}
	for _, kind := range []string{"target", "sni", "port", "old", "future", "count"} {
		r := valid
		switch kind {
		case "target":
			r.Target = "different.test:443"
		case "sni":
			r.Host = "different.test"
		case "port":
			r.Port = 80
		case "old":
			r.CheckedAt = time.Now().Add(-3 * time.Minute).Format(time.RFC3339)
		case "future":
			r.CheckedAt = time.Now().Add(3 * time.Minute).Format(time.RFC3339)
		}
		raw := encode(r)
		if kind == "count" {
			raw = encode(r, r)
		}
		if _, err := decodeAgentRealityResults(raw, targets, server); err == nil {
			t.Fatal("accepted mismatched result", kind)
		}
	}
}
func TestAgentRealityQueueAndCapability(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server := store.Record{Collection: "servers", ID: "scan-agent", Data: map[string]any{"name": "Scan Agent", "connection": "WebSocket"}}
	if _, err := a.DB.SaveRecord(ctx, server); err != nil {
		t.Fatal(err)
	}
	users, _ := a.DB.ListUsers(ctx)
	targets, _ := parseRealityScanTargets("example.test")
	if _, err := a.scanRealityAgent(ctx, users[0], server.ID, targets); err == nil {
		t.Fatal("offline accepted")
	}
	a.peers[server.ID] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"reality_scan": true}}
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-ticker.C:
			}
			tasks, err := a.DB.ListTasks(ctx, server.ID, 10)
			if err != nil {
				done <- err
				return
			}
			if len(tasks) == 0 {
				continue
			}
			task := tasks[0]
			var cmd agentwire.Command
			if err = json.Unmarshal(task.Input, &cmd); err != nil {
				done <- err
				return
			}
			if cmd.Action != "reality.scan" || text(cmd.Params, "targets") != "example.test:443" || dateTime(text(cmd.Params, "expiresAt")).IsZero() {
				done <- store.ErrInvalid
				return
			}
			task.Result, _ = json.Marshal(map[string]any{"results": []realityScanResult{{Target: "example.test:443", Host: "example.test", Port: 443, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}}})
			task.Status = "success"
			_, err = a.DB.SaveTask(ctx, task)
			done <- err
			return
		}
	}()
	results, err := a.scanRealityAgent(ctx, users[0], server.ID, targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ServerID != server.ID {
		t.Fatal("missing agent origin")
	}
}
