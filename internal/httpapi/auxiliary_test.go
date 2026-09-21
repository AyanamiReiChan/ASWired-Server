package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"testing"
)

func TestLegacyAuxiliaryManagementBlocksPublishingAndQueuesShutdown(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	inbound, e := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "aux", Data: map[string]any{"name": "AnyTLS", "serverId": "server", "tag": "aux-anytls", "protocol": "AnyTLS", "port": 9443, "status": "启用"}})
	if e != nil {
		t.Fatal(e)
	}
	actor, _ := a.DB.UserByID(ctx, "admin")
	if _, e = a.queueCompile(ctx, actor, "server"); e == nil {
		t.Fatal("unsupported managed listener compiled")
	}
	if _, e = a.compileAuxiliary(ctx, "server"); e == nil {
		t.Fatal("unsupported auxiliary listener compiled")
	}
	if _, _, e = a.compileAuxiliaryInbound(ctx, inbound); e == nil {
		t.Fatal("unsupported auxiliary listener received managed users")
	}
	a.reconcileAuxiliary(ctx, actor)
	state, e := a.DB.GetRecord(ctx, "_auxiliarySync", "server")
	if e != nil || text(state.Data, "status") != "blocked" {
		t.Fatal("legacy listener was not blocked")
	}
	task, e := a.DB.GetTask(ctx, text(state.Data, "taskId"))
	if e != nil {
		t.Fatal(e)
	}
	var command agentwire.Command
	if e = json.Unmarshal(task.Input, &command); e != nil {
		t.Fatal(e)
	}
	if task.Kind != "mihomo.config.apply" || len(command.Params["listeners"].([]any)) != 0 {
		t.Fatal("legacy listener shutdown not queued")
	}
	saved, e := a.DB.GetRecord(ctx, "inbounds", inbound.ID)
	if e != nil || saved.Version != inbound.Version || text(saved.Data, "protocol") != "AnyTLS" {
		t.Fatal("legacy inbound was changed")
	}
}

func TestOldAuxiliaryCompletionCannotRepublishListeners(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	command := agentwire.Command{ID: "old-config", Action: "core.config.apply", Params: map[string]any{"auxiliary": map[string]any{"listeners": []any{map[string]any{"type": "anytls"}}}}}
	raw, _ := json.Marshal(command)
	a.finishAuxiliaryCompile(ctx, store.Task{ID: command.ID, ServerID: "server", ActorID: "admin", Kind: command.Action, Status: "success", Input: raw})
	tasks, e := a.DB.ListTasks(ctx, "server", 100)
	if e != nil || len(tasks) != 0 {
		t.Fatal("old deferred listener was republished")
	}
}
