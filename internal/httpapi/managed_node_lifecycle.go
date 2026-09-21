package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

// Delete the authoritative inbound and its projection in the same transaction
// as the removal command. Keep explicit plan IDs: removing the last ID would
// turn a restricted plan into an all-nodes plan.
func (a *App) deleteManagedInbound(w http.ResponseWriter, r *http.Request, rec store.Record) {
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	ctx := r.Context()
	inboundID := rec.ID
	if rec.Collection == "nodes" {
		inboundID = text(rec.Data, "inboundId")
	}
	inbound, err := a.DB.GetRecord(ctx, "inbounds", inboundID)
	if err != nil {
		fail(w, 409, "inbound_missing", "关联入站已改变，请刷新后重试")
		return
	}
	server, err := a.DB.GetRecord(ctx, "servers", text(inbound.Data, "serverId"))
	if err != nil || !nativeServer(server) {
		fail(w, 409, "server_unavailable", "无法为关联服务器创建删除任务")
		return
	}
	if err := a.rememberManagedInboundTags(ctx, inbound); err != nil {
		fail(w, 503, "storage_error", "旧入站任务归属保存失败，请重试")
		return
	}
	config, err := a.compileServerExcluding(ctx, server, true, inbound.ID)
	if err != nil {
		fail(w, 400, "invalid_remaining_config", err.Error())
		return
	}
	deleted := []store.Record{inbound}
	if node, e := a.DB.GetRecord(ctx, "nodes", "inbound-"+inbound.ID); e == nil {
		deleted = append(deleted, node)
	} else if !errors.Is(e, store.ErrNotFound) {
		fail(w, 503, "storage_error", "无法读取关联节点")
		return
	}
	actor := current(r)
	aux, err := a.compileAuxiliaryExcluding(ctx, server.ID, inbound.ID)
	if err != nil {
		fail(w, 400, "invalid_remaining_config", err.Error())
		return
	}
	command := agentwire.Command{ID: newID(), Action: "core.config.apply", Params: map[string]any{"config": config, "managedInbounds": true, "managedProfileVersion": 2, "auxiliary": aux}}
	raw, _ := json.Marshal(command)
	task := store.Task{ID: command.ID, ServerID: server.ID, ActorID: actor.ID, Kind: command.Action, Status: "queued", Input: raw}
	tombstone := store.Record{Collection: "_deletedManagedInbounds", ID: inbound.ID, Data: map[string]any{"serverId": server.ID, "tag": text(inbound.Data, "tag"), "deletedAt": time.Now().UTC(), "taskId": task.ID}}
	if old, e := a.DB.GetRecord(ctx, tombstone.Collection, tombstone.ID); e == nil {
		tombstone.Version = old.Version
	} else if !errors.Is(e, store.ErrNotFound) {
		fail(w, 503, "storage_error", "无法读取删除记录")
		return
	}
	task, err = a.DB.CreateTaskWithChanges(ctx, task, []store.Record{tombstone}, deleted)
	if err != nil {
		fail(w, 409, "delete_conflict", "删除未提交，记录已改变，请刷新重试")
		return
	}
	a.audit(ctx, actor, "inbound.delete", inbound.ID, map[string]any{"taskId": task.ID, "nodeId": "inbound-" + inbound.ID})
	respond(w, 200, map[string]any{"success": true, "task": taskRow(task), "runtimePending": true})
}

func (a *App) rejectDeletedInboundReplay(ctx context.Context, serverID string, config map[string]any) error {
	deleted, err := a.DB.ListRecords(ctx, "_deletedManagedInbounds", "")
	if err != nil {
		return err
	}
	retired := map[string]bool{}
	for _, row := range deleted {
		if text(row.Data, "serverId") == serverID {
			retired[text(row.Data, "tag")] = true
		}
	}
	inbounds, _ := config["inbounds"].([]any)
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		if retired[text(inbound, "tag")] {
			return errors.New("配置包含已删除入站，不能重试旧配置；请从当前服务器重新发布")
		}
	}
	return nil
}
