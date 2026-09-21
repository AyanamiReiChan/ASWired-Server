package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"strconv"
	"time"
)

func (a *App) networkAction(ctx context.Context, u store.User, in actionInput) (bool, map[string]any, error) {
	action := in.Action
	if action == "forward.apply" || action == "forward.disable" {
		group, e := a.DB.GetRecord(ctx, "forwards", in.TargetID)
		if e != nil {
			return true, nil, e
		}
		if action == "forward.disable" {
			group.Data["status"] = "禁用"
			if _, e = a.DB.SaveRecord(ctx, group); e != nil {
				return true, nil, e
			}
		}
		serverID := text(group.Data, "serverId")
		groups, e := a.DB.ListRecords(ctx, "forwards", "")
		if e != nil {
			return true, nil, e
		}
		rules := []any{}
		for _, record := range groups {
			if text(record.Data, "serverId") != serverID || disabledStatus(record.Data) {
				continue
			}
			raw, _ := record.Data["rules"].([]any)
			for index, item := range raw {
				rule, ok := item.(map[string]any)
				if !ok {
					return true, nil, errors.New("转发规则须为对象")
				}
				rule = clone(rule)
				rule["id"] = record.ID + ":" + strconv.Itoa(index)
				rules = append(rules, rule)
			}
		}
		task, e := a.queue(ctx, u, serverID, "network.forward.apply", map[string]any{"rules": rules})
		return true, map[string]any{"task": taskRow(task)}, e
	}
	if action == "forward.chain.apply" {
		out, e := a.beginForwardChain(ctx, u, in.TargetID)
		return true, out, e
	}
	if action == "forward.chain.status" {
		state, e := a.DB.GetRecord(ctx, "_forwardChains", in.TargetID)
		return true, map[string]any{"chain": rowOf(state, false)}, e
	}
	if action == "forward.ledger" {
		records, e := a.DB.ListRecords(ctx, "_forwardLedger", "")
		if e != nil {
			return true, nil, e
		}
		rows := []any{}
		for _, record := range records {
			if in.TargetID == "" || text(record.Data, "serverId") == in.TargetID {
				rows = append(rows, rowOf(record, false))
			}
		}
		return true, map[string]any{"rows": rows, "source": "forward raw socket counters"}, nil
	}
	switch action {
	case "network.forward.apply", "network.forward.status", "network.wireguard.apply", "network.wireguard.remove", "network.wireguard.status", "network.warp.apply", "network.warp.remove", "network.warp.status", "network.quality":
		task, e := a.queue(ctx, u, in.TargetID, action, in.Params)
		return true, map[string]any{"task": taskRow(task)}, e
	}
	return false, nil, nil
}
func counterInteger(value any) int64 {
	switch value := value.(type) {
	case json.Number:
		n, _ := value.Int64()
		return n
	case int64:
		return value
	case int:
		return int64(value)
	case float64:
		return int64(value)
	}
	return 0
}
func (a *App) accountForwards(ctx context.Context, serverID string, snapshot map[string]any) {
	sampled := counterInteger(snapshot["sampled_at"])
	if sampled == 0 {
		return
	}
	items, _ := snapshot["items"].([]any)
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rule, _ := entry["rule"].(map[string]any)
		id := text(rule, "id")
		generation := text(entry, "generation")
		if id == "" || generation == "" {
			continue
		}
		cursorID := hashOpaque(serverID + "\n" + id)
		old, _ := a.DB.GetRecord(ctx, "_forwardCounters", cursorID)
		if sampled <= counterInteger(old.Data["sampled_at"]) {
			continue
		}
		received, sent := counterInteger(entry["received_bytes"]), counterInteger(entry["sent_bytes"])
		if received < 0 || sent < 0 {
			continue
		}
		deltaReceived, deltaSent := int64(0), int64(0)
		gap := true
		if text(old.Data, "generation") == generation && received >= counterInteger(old.Data["received_bytes"]) && sent >= counterInteger(old.Data["sent_bytes"]) {
			deltaReceived = received - counterInteger(old.Data["received_bytes"])
			deltaSent = sent - counterInteger(old.Data["sent_bytes"])
			gap = false
		}
		state := store.Record{Collection: "_forwardCounters", ID: cursorID, Version: old.Version, Data: map[string]any{"generation": generation, "sampled_at": sampled, "received_bytes": received, "sent_bytes": sent}}
		ledger := store.Record{Collection: "_forwardLedger", ID: hashOpaque(cursorID + "/" + fmt.Sprint(sampled)), Data: map[string]any{"serverId": serverID, "ruleId": id, "received_bytes": deltaReceived, "sent_bytes": deltaSent, "generation": generation, "sampled_at": sampled, "gap": gap, "source": "forward"}}
		_, _ = a.DB.CompareAndSaveRecords(ctx, []store.Record{state, ledger})
	}
	old, _ := a.DB.GetRecord(ctx, "_forwardState", serverID)
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_forwardState", ID: serverID, Version: old.Version, Data: snapshot})
}
func (a *App) recordNetworkQuality(ctx context.Context, task store.Task, result map[string]any) {
	var cmd agentwire.Command
	if json.Unmarshal(task.Input, &cmd) != nil {
		return
	}
	sampleID := defaultText(cmd.Params, "sample_id", task.ID)
	data := clone(result)
	data["sampleId"] = sampleID
	data["method"] = cmd.Params["method"]
	_ = a.DB.AddMetric(ctx, store.Metric{ID: "quality-" + task.ID, ServerID: "quality:" + task.ServerID, RecordedAt: time.Now().UTC(), Values: data})
}
