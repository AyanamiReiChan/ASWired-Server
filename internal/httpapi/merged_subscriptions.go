package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// A missing or null selection preserves the original all-current-instances
// behavior. A non-nil empty selection is deliberately empty, never all.
func mergedSelection(rec store.Record) map[string]bool {
	value, exists := rec.Data["subscriptionIds"]
	if !exists || value == nil {
		return nil
	}
	selected := map[string]bool{}
	for _, id := range stringList(value) {
		selected[id] = true
	}
	return selected
}

func validateMergedSelection(raw json.RawMessage, subs []store.Record) (any, error) {
	if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil || ids == nil || len(ids) > 1000 {
		return nil, errors.New("请选择有效的套餐实例，一次最多选择 1000 个")
	}
	owned := make(map[string]bool, len(subs))
	for _, sub := range subs {
		owned[sub.ID] = true
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || !owned[id] || seen[id] {
			return nil, errors.New("所选套餐实例不存在、重复或不属于当前账户，请刷新后重新选择")
		}
		seen[id] = true
	}
	// Stable storage does not affect the ordering of the generated nodes.
	sort.Strings(ids)
	return ids, nil
}

func (a *App) mergedProjection(ctx context.Context, rec store.Record, subs []store.Record) map[string]any {
	rows := make([]map[string]any, 0, len(subs))
	for _, sub := range subs {
		row := map[string]any{
			"id": sub.ID, "name": text(sub.Data, "name"), "planId": text(sub.Data, "planId"),
			"plan": text(sub.Data, "plan"), "status": text(sub.Data, "status"), "expires": text(sub.Data, "expires"),
			"active": true,
		}
		if err := a.subscriptionActive(ctx, sub); err != nil {
			row["active"] = false
			row["unavailableReason"] = err.Error()
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return text(rows[i], "id") < text(rows[j], "id") })
	return map[string]any{
		"enabled": boolean(rec.Data, "enabled"), "url": text(rec.Data, "url"),
		"subscriptionIds": rec.Data["subscriptionIds"], "subscriptions": rows,
	}
}
