package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

const xraySyncInterval = 5 * time.Minute

// Cache records use the same encrypted storage as configuration history and
// remain outside public collections and the workspace state response.
func (a *App) xrayCache(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.DB.GetRecord(r.Context(), "servers", id); err != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"config": nil, "syncedAt": nil, "syncIntervalSeconds": int(xraySyncInterval.Seconds())}
	if cache, err := a.DB.GetRecord(r.Context(), "_xrayCache", id); err == nil {
		for _, key := range []string{"config", "syncedAt", "lastError", "taskId"} {
			if v, ok := cache.Data[key]; ok {
				data[key] = v
			}
		}
		if data["syncedAt"] == nil {
			data["syncedAt"] = cache.Data["previousSyncedAt"]
			data["refreshPending"] = cache.Data["invalidatedAt"] != nil
		}
	}
	if observation, err := a.DB.GetRecord(r.Context(), "_observations", id); err == nil {
		if core, ok := observation.Data["core"].(map[string]any); ok {
			data["core"] = map[string]any{"running": core["running"], "core_version": core["core_version"]}
			data["statusAt"] = observation.UpdatedAt
		}
	}
	respond(w, 200, data)
}

// Called on authenticated heartbeats, so offline/disabled servers never build
// up queued polls. A persisted attempt timestamp also limits retries on errors.
func (a *App) syncXrayCache(ctx context.Context, id string, now time.Time) {
	a.xrayCacheMu.Lock()
	defer a.xrayCacheMu.Unlock()
	cache, _ := a.DB.GetRecord(ctx, "_xrayCache", id)
	if cache.Data == nil {
		cache = store.Record{Collection: "_xrayCache", ID: id, Data: map[string]any{}}
	}
	for _, key := range []string{"lastAttempt", "syncedAt"} {
		if stamp, err := time.Parse(time.RFC3339Nano, text(cache.Data, key)); err == nil && now.Sub(stamp) < xraySyncInterval {
			return
		}
	}
	for _, kind := range []string{"core.config.get", "core.config.apply", "core.config.restore"} {
		active, err := a.DB.HasActiveTask(ctx, id, kind)
		if err != nil || active {
			return
		}
	}
	command := agentwire.Command{ID: newID(), Action: "core.config.get"}
	input, _ := json.Marshal(command)
	task, err := a.DB.SaveTask(ctx, store.Task{ID: command.ID, ServerID: id, ActorID: "system:xray-cache", Kind: command.Action, Status: "queued", Input: input, CreatedAt: now.UTC(), UpdatedAt: now.UTC()})
	if err != nil {
		return
	}
	cache.Data["lastAttempt"] = now.UTC().Format(time.RFC3339Nano)
	cache.Data["taskId"] = task.ID
	_, _ = a.DB.SaveRecord(ctx, cache)
}

func (a *App) finishXrayCache(ctx context.Context, task store.Task, result agentwire.Result) {
	if task.Kind != "core.config.get" && task.Kind != "core.config.apply" && task.Kind != "core.config.restore" {
		return
	}
	a.xrayCacheMu.Lock()
	defer a.xrayCacheMu.Unlock()
	cache, _ := a.DB.GetRecord(ctx, "_xrayCache", task.ServerID)
	if cache.Data == nil {
		cache = store.Record{Collection: "_xrayCache", ID: task.ServerID, Data: map[string]any{}}
	}
	if task.Kind != "core.config.get" {
		if result.Status != "success" {
			return
		}
		// Keep the previous snapshot available until the applied config is read back.
		delete(cache.Data, "lastAttempt")
		cache.Data["invalidatedAt"] = task.UpdatedAt.UTC().Format(time.RFC3339Nano)
		cache.Data["previousSyncedAt"] = cache.Data["syncedAt"]
		delete(cache.Data, "syncedAt")
	} else {
		if invalidated, err := time.Parse(time.RFC3339Nano, text(cache.Data, "invalidatedAt")); err == nil && task.CreatedAt.Before(invalidated) {
			return
		}
		if synced, err := time.Parse(time.RFC3339Nano, text(cache.Data, "syncedAt")); err == nil && task.CreatedAt.Before(synced) {
			return
		}
		cache.Data["lastAttempt"] = task.UpdatedAt.UTC().Format(time.RFC3339Nano)
		if cfg, ok := result.Data["config"].(map[string]any); result.Status == "success" && ok {
			cache.Data["config"] = cfg
			cache.Data["syncedAt"] = task.UpdatedAt.UTC().Format(time.RFC3339Nano)
			delete(cache.Data, "lastError")
			delete(cache.Data, "invalidatedAt")
			delete(cache.Data, "previousSyncedAt")
		} else {
			cache.Data["lastError"] = "最近一次配置同步未成功，保留上次快照"
		}
	}
	_, _ = a.DB.SaveRecord(ctx, cache)
}
