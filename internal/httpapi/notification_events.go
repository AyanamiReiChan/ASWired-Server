package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"time"
)

func (a *App) emitEvent(ctx context.Context, event, ownerID, targetID, message string, details map[string]any) {
	if len(message) > 3500 {
		message = message[:3500]
	}
	id := hashOpaque(event + "\n" + ownerID + "\n" + targetID)
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_notificationEvents", ID: id, OwnerID: ownerID, Data: map[string]any{"event": event, "targetId": targetID, "message": message, "details": details, "status": "pending", "occurredAt": time.Now().UTC().Format(time.RFC3339Nano)}})
}
func (a *App) maintainNotifications(ctx context.Context) {
	var settings map[string]any
	_ = a.DB.GetSetting(ctx, "settings", &settings)
	enabled, _ := settings["notificationEvents"].(map[string]any)
	events, e := a.DB.ListRecords(ctx, "_notificationEvents", "")
	if e != nil {
		return
	}
	queued := 0
	for _, event := range events {
		if text(event.Data, "status") != "pending" {
			continue
		}
		if enabled[text(event.Data, "event")] != true {
			event.Data["status"] = "disabled"
			_, _ = a.DB.SaveRecord(ctx, event)
			continue
		}
		event := event
		a.startJob(ctx, "notification:"+event.ID, func(ctx context.Context) { a.deliverEvent(ctx, event) })
		queued++
		if queued >= 8 {
			break
		}
	}
}
func (a *App) deliverEvent(ctx context.Context, event store.Record) {
	latest, e := a.DB.GetRecord(ctx, "_notificationEvents", event.ID)
	if e != nil || text(latest.Data, "status") != "pending" {
		return
	}
	latest.Data["status"] = "sending"
	latest, e = a.DB.SaveRecord(ctx, latest)
	if e != nil {
		return
	}
	params := map[string]any{"event": text(event.Data, "event"), "message": text(event.Data, "message")}
	var deliveryErr error
	sent := 0
	if event.OwnerID != "" {
		pref, _ := a.DB.GetRecord(ctx, "_telegramPreferences", event.OwnerID)
		if pref.Data["enabled"] == false {
			latest.Data["status"] = "muted"
			_, _ = a.DB.SaveRecord(ctx, latest)
			return
		}
		u, e := a.DB.UserByID(ctx, event.OwnerID)
		if e != nil || u.Disabled {
			deliveryErr = errors.New("接收账户不可用")
		} else {
			bindings, e := a.DB.ListRecords(ctx, "_telegramBindings", event.OwnerID)
			if e != nil {
				deliveryErr = e
			} else if len(bindings) == 0 {
				deliveryErr = errors.New("接收账户尚未绑定Telegram")
			} else {
				for _, binding := range bindings {
					params["channel"] = "telegram"
					params["chatId"] = text(binding.Data, "chatId")
					_, e = a.notificationTest(ctx, u, "", params)
					if e != nil {
						deliveryErr = e
						break
					}
					sent++
				}
			}
		}
	} else {
		_, deliveryErr = a.notificationTest(ctx, store.User{ID: "notification-service", Role: "admin"}, "", params)
		if deliveryErr == nil {
			sent++
		}
	}
	latest.Data["status"] = "sent"
	latest.Data["completedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	latest.Data["delivered"] = sent
	if deliveryErr != nil {
		latest.Data["status"] = "failed"
		latest.Data["error"] = deliveryErr.Error()
	}
	_, _ = a.DB.SaveRecord(ctx, latest)
}
func (a *App) dailyMessage(ctx context.Context, now time.Time) (string, error) {
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(-24 * time.Hour).UTC()
	end := start.Add(24 * time.Hour)
	var raw, weighted int64
	e := a.DB.DB().QueryRowContext(ctx, a.DB.Bind("SELECT COALESCE(SUM(raw_bytes),0),COALESCE(SUM(weighted_bytes),0) FROM traffic_ledger WHERE sampled_at>=? AND sampled_at<?"), start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)).Scan(&raw, &weighted)
	if e != nil {
		return "", e
	}
	servers, e := a.DB.ListRecords(ctx, "servers", "")
	if e != nil {
		return "", e
	}
	online := 0
	for _, s := range servers {
		_, ok, _ := a.selectedObservation(ctx, s)
		if ok {
			online++
		}
	}
	lines := []string{"ASWired 日报 · " + start.Format("2006-01-02"), fmt.Sprintf("昨日原始代理流量 %.3f GiB；计费用量 %.3f GiB", float64(raw)/(1<<30), float64(weighted)/(1<<30)), fmt.Sprintf("当前在线观测 %d / %d 台", online, len(servers)), "按实际收到的样本汇总，缺失时段未估算。"}
	return strings.Join(lines, "\n"), nil
}
func (a *App) subscriptionChangeEvents(ctx context.Context) {
	subs, e := a.DB.ListRecords(ctx, "subscriptions", "")
	if e != nil {
		return
	}
	for _, sub := range subs {
		active := a.subscriptionActive(ctx, sub) == nil
		state := defaultText(sub.Data, "effectiveStatus", text(sub.Data, "status"))
		old, _ := a.DB.GetRecord(ctx, "_subscriptionEventState", sub.ID)
		fingerprint := fmt.Sprintf("%t|%s|%s|%v|%v", active, state, text(sub.Data, "expires"), sub.Data["nodeIds"], sub.Data["planId"])
		if text(old.Data, "fingerprint") == fingerprint {
			continue
		}
		_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_subscriptionEventState", ID: sub.ID, OwnerID: sub.OwnerID, Version: old.Version, Data: map[string]any{"fingerprint": fingerprint}})
		if e != nil {
			continue
		}
		if old.Version == 0 {
			continue
		}
		event := "subscription.changed"
		if !active {
			event = "subscription.unavailable"
		}
		a.emitEvent(ctx, event, sub.OwnerID, sub.ID+"/"+fmt.Sprint(sub.Version), "套餐 "+text(sub.Data, "name")+" 状态已更新："+state, nil)
	}
}
