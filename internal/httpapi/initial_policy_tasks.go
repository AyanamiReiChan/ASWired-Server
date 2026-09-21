package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

const unusedInitialPolicyMessage = "自动生成的初始空策略已失效：没有需要同步的策略，未向 Agent 下发"

func (a *App) noOtherPolicyTask(ctx context.Context, serverID, exceptID string) bool {
	exists, err := a.DB.HasOtherTask(ctx, serverID, "core.policy.apply", exceptID)
	return err == nil && !exists
}

func (a *App) retireUnusedInitialPolicyTasks(ctx context.Context) {
	states, err := a.DB.ListRecords(ctx, "_policySync", "")
	if err != nil {
		return
	}
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return
	}
	configured := map[string]bool{}
	for _, inbound := range inbounds {
		configured[text(inbound.Data, "serverId")] = true
	}
	raw, _ := json.Marshal(map[string]any{"policies": []any{}})
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	for _, state := range states {
		if state.Version != 1 || configured[state.ID] || text(state.Data, "digest") != digest {
			continue
		}
		policies, ok := state.Data["policies"].([]any)
		if !ok || len(policies) != 0 {
			continue
		}
		server, err := a.DB.GetRecord(ctx, "servers", state.ID)
		if err != nil || !nativeServer(server) {
			continue
		}
		task, err := a.DB.GetTask(ctx, text(state.Data, "taskId"))
		if err != nil || task.ServerID != state.ID || task.Kind != "core.policy.apply" || task.Status != "queued" || len(task.Result) > 0 {
			continue
		}
		var command agentwire.Command
		if json.Unmarshal(task.Input, &command) != nil || command.ID != task.ID || command.Action != task.Kind || len(command.Params) != 1 {
			continue
		}
		policies, ok = command.Params["policies"].([]any)
		if !ok || len(policies) != 0 || !a.noOtherPolicyTask(ctx, state.ID, task.ID) {
			continue
		}
		task.Status = "superseded"
		task.Error = unusedInitialPolicyMessage
		task.UpdatedAt = time.Now().UTC()
		_, _ = a.DB.SaveTask(ctx, task)
	}
}
