package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func planTemplateID(row map[string]any, format string) string {
	if format == "stash" {
		format = "clash"
	}
	ids, _ := row["templateIds"].(map[string]any)
	return text(ids, format)
}

func (a *App) validatePlanManagement(ctx context.Context, row map[string]any) error {
	if strings.TrimSpace(text(row, "name")) == "" {
		return errors.New("请填写套餐名称")
	}
	if factor := number(row, "directionFactor"); factor != 1 && factor != 2 {
		return errors.New("流量统计倍率须为 1 或 2")
	}
	for _, key := range []string{"limit", "price"} {
		if v := row[key]; v != nil && (!finiteNumeric(v) || number(row, key) < 0) {
			return fmt.Errorf("%s 须为非负数", key)
		}
	}
	if raw := row["templateIds"]; raw != nil {
		ids, ok := raw.(map[string]any)
		if !ok {
			return errors.New("模板配置须为对象")
		}
		for kind, value := range ids {
			if kind != "clash" && kind != "surge" && kind != "loon" {
				return errors.New("不支持的套餐模板类型")
			}
			id, ok := value.(string)
			if !ok {
				return errors.New("模板标识须为字符串")
			}
			if id == "" {
				continue
			}
			rec, err := a.DB.GetRecord(ctx, "policies", id)
			if err != nil || !templateMatches(rec.Data, kind) {
				return fmt.Errorf("%s 模板不存在或类型不匹配", kind)
			}
		}
	}
	if raw := row["nodeNames"]; raw != nil {
		names, ok := raw.(map[string]any)
		if !ok || len(names) > 500 {
			return errors.New("节点别名须为至多 500 项的对象")
		}
		for id, value := range names {
			name, ok := value.(string)
			if id == "" || !ok || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
				return errors.New("节点别名无效或过长")
			}
		}
	}
	if raw := row["nodeTraffic"]; raw != nil {
		entries, ok := raw.(map[string]any)
		if !ok || len(entries) > 500 {
			return errors.New("节点流量配置须为至多 500 项的对象")
		}
		for id, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				return errors.New("节点流量配置无效")
			}
			if len(entry) == 0 {
				continue
			}
			node, err := a.DB.GetRecord(ctx, "nodes", id)
			if err != nil || !boolean(node.Data, "managedInbound") || text(node.Data, "inboundId") == "" {
				return errors.New("仅受管入站支持逐节点流量倍率与额度")
			}
			for key, value := range entry {
				if key != "multiplier" && key != "limit" {
					return errors.New("节点流量配置仅支持倍率和额度")
				}
				if !finiteNumeric(value) || number(entry, key) < 0 || number(entry, key) > 1e9 {
					return errors.New("节点流量值须为非负数，且不超过十亿")
				}
			}
		}
	}
	return nil
}

func planNodeTraffic(plan map[string]any, nodeID string) map[string]any {
	entries, _ := plan["nodeTraffic"].(map[string]any)
	entry, _ := entries[nodeID].(map[string]any)
	return entry
}

// Uses the existing local ledger; no extra requests are sent to an Agent.
func (a *App) planNodeQuotaExceeded(ctx context.Context, sub store.Record, plan map[string]any, nodeID, inboundID string) (bool, error) {
	limit := number(planNodeTraffic(plan, nodeID), "limit")
	if limit <= 0 {
		return false, nil
	}
	start, end := dateTime(text(sub.Data, "cycleStart")), dateTime(text(sub.Data, "cycleEnd"))
	if start.IsZero() {
		start = sub.CreatedAt
	}
	if end.IsZero() {
		end = time.Now().AddDate(100, 0, 0)
	}
	used, err := a.DB.NodeTrafficUsage(ctx, sub.ID, text(sub.Data, "credentialEmail")+"."+inboundID, start.UnixMilli(), end.UnixMilli())
	return used >= limit*gib, err
}
