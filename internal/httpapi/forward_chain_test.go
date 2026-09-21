package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"testing"
	"time"
)

func TestForwardChainValidatesBeforeDispatchAndWaitsForSuccess(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	for _, id := range []string{"entry", "exit"} {
		_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: id, Data: map[string]any{"address": id + ".example.com"}})
		if e != nil {
			t.Fatal(e)
		}
	}
	group, e := a.DB.SaveRecord(ctx, store.Record{Collection: "forwards", ID: "chain", Data: map[string]any{"name": "chain", "protocol": "tcp", "target": "target.example.com:443", "hops": []any{map[string]any{"serverId": "missing", "listen": "127.0.0.1:21000"}, map[string]any{"serverId": "exit", "listen": "127.0.0.1:22000"}}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.beginForwardChain(ctx, u, group.ID); e == nil {
		t.Fatal("invalid hop accepted")
	}
	tasks, _ := a.DB.ListTasks(ctx, "", 100)
	if len(tasks) != 0 {
		t.Fatal("invalid topology dispatched a partial chain")
	}
	group.Data["hops"] = []any{map[string]any{"serverId": "entry", "listen": "127.0.0.1:21000"}, map[string]any{"serverId": "exit", "listen": "127.0.0.1:22000"}}
	if _, e = a.DB.SaveRecord(ctx, group); e != nil {
		t.Fatal(e)
	}
	if _, e = a.beginForwardChain(ctx, u, group.ID); e != nil {
		t.Fatal(e)
	}
	tasks, _ = a.DB.ListTasks(ctx, "", 100)
	if len(tasks) != 1 || tasks[0].ServerID != "exit" {
		t.Fatal("entry opened before exit acknowledgment")
	}
	a.maintainForwardChains(ctx)
	again, _ := a.DB.ListTasks(ctx, "", 100)
	if len(again) != 1 {
		t.Fatal("duplicate chain dispatch")
	}
	task := tasks[0]
	task.Status = "success"
	task.UpdatedAt = time.Now()
	if _, e = a.DB.SaveTask(ctx, task); e != nil {
		t.Fatal(e)
	}
	a.maintainForwardChains(ctx)
	tasks, _ = a.DB.ListTasks(ctx, "entry", 100)
	if len(tasks) != 1 {
		t.Fatal("ready exit did not dispatch entry")
	}
	task = tasks[0]
	task.Status = "failed"
	task.UpdatedAt = time.Now()
	if _, e = a.DB.SaveTask(ctx, task); e != nil {
		t.Fatal(e)
	}
	a.maintainForwardChains(ctx)
	state, _ := a.DB.GetRecord(ctx, "_forwardChains", group.ID)
	if text(state.Data, "status") != "failed" {
		t.Fatal("failed bind presented as ready chain")
	}
}
