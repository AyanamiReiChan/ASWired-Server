package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strconv"
	"strings"
	"time"
)

func (a *App) telegramExtraCommand(ctx context.Context, user store.User, chat string, parts []string) (bool, string, error) {
	switch parts[0] {
	case "/nodes":
		subs, e := a.DB.ListRecords(ctx, "subscriptions", user.ID)
		if e != nil {
			return true, "", e
		}
		seen := map[string]bool{}
		lines := []string{}
		for _, sub := range subs {
			nodes, _ := a.eligibleNodes(ctx, sub)
			for _, node := range nodes {
				if !seen[node.ID] {
					seen[node.ID] = true
					lines = append(lines, text(node.Data, "name")+" · "+text(node.Data, "protocol"))
				}
			}
		}
		if len(lines) == 0 {
			return true, "暂无可用节点", nil
		}
		return true, strings.Join(lines, "\n"), nil
	case "/notify":
		pref, _ := a.DB.GetRecord(ctx, "_telegramPreferences", user.ID)
		if len(parts) == 1 {
			return true, fmt.Sprintf("事件通知：%t。使用 /notify on 或 /notify off", pref.Data["enabled"] != false), nil
		}
		if len(parts) != 2 || parts[1] != "on" && parts[1] != "off" {
			return true, "", errors.New("使用 /notify on 或 /notify off")
		}
		_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_telegramPreferences", ID: user.ID, OwnerID: user.ID, Version: pref.Version, Data: map[string]any{"enabled": parts[1] == "on"}})
		return true, "通知偏好已保存", e
	case "/unbind":
		code := newID()
		_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_telegramUnbind", ID: hashOpaque(code), OwnerID: user.ID, Data: map[string]any{"chatId": chat, "expires": time.Now().Add(time.Minute).Unix()}})
		return true, "一分钟内发送 /unbindconfirm " + code + " 确认解绑当前Telegram。", e
	case "/unbindconfirm":
		if len(parts) != 2 {
			return true, "", errors.New("使用 /unbind 生成确认码")
		}
		pending, e := a.DB.GetRecord(ctx, "_telegramUnbind", hashOpaque(parts[1]))
		if e != nil || pending.OwnerID != user.ID || text(pending.Data, "chatId") != chat || boolean(pending.Data, "used") || number(pending.Data, "expires") < float64(time.Now().Unix()) {
			return true, "", errors.New("确认码无效或过期")
		}
		pending.Data["used"] = true
		if _, e = a.DB.SaveRecord(ctx, pending); e != nil {
			return true, "", e
		}
		e = a.DB.DeleteRecord(ctx, "_telegramBindings", chat)
		return true, "当前Telegram已解绑", e
	case "/redeem":
		if len(parts) != 2 {
			return true, "", errors.New("使用 /redeem 兑换码")
		}
		_, result, e := a.membershipAction(ctx, user, actionInput{Action: "membership.redeem", Params: map[string]any{"code": parts[1]}})
		return true, fmt.Sprint(result["message"]), e
	case "/renew":
		if len(parts) != 2 {
			return true, "", errors.New("使用 /renew 套餐订阅ID；/usage 可查看ID")
		}
		_, _, e := a.membershipAction(ctx, user, actionInput{Action: "subscription.renewal.declare", TargetID: parts[1], Params: map[string]any{"note": "Telegram成员续费声明"}})
		return true, "续费声明已提交，请等待管理员核对。", e
	case "/find", "/codescreate", "/codesrevoke", "/requests":
		if user.Role != "admin" {
			return true, "", errors.New("需要管理员权限")
		}
		if parts[0] == "/find" {
			if len(parts) != 2 {
				return true, "", errors.New("使用 /find 用户名片段")
			}
			users, e := a.DB.ListUsers(ctx)
			if e != nil {
				return true, "", e
			}
			lines := []string{}
			for _, found := range users {
				if strings.Contains(strings.ToLower(found.Username), strings.ToLower(parts[1])) {
					lines = append(lines, found.Username+" · "+found.ID+fmt.Sprintf(" · 停用=%t", found.Disabled))
					if len(lines) >= 20 {
						break
					}
				}
			}
			return true, strings.Join(lines, "\n"), nil
		}
		if parts[0] == "/requests" {
			rows, e := a.DB.ListRecords(ctx, "_renewalDeclarations", "")
			if e != nil {
				return true, "", e
			}
			lines := []string{}
			for _, row := range rows {
				if text(row.Data, "status") == "待核对" {
					lines = append(lines, row.ID+" · "+text(row.Data, "subscriptionId"))
				}
			}
			return true, strings.Join(lines, "\n") + "\n请在网站套餐页核对后确认。", nil
		}
		if parts[0] == "/codesrevoke" {
			if len(parts) != 2 {
				return true, "", errors.New("使用 /codesrevoke 兑换码ID")
			}
			_, _, e := a.membershipAction(ctx, user, actionInput{Action: "membership.code.revoke", TargetID: parts[1]})
			return true, "兑换码已吊销", e
		}
		if len(parts) != 4 {
			return true, "", errors.New("使用 /codescreate 套餐ID 套餐天数 可用次数")
		}
		days, e := strconv.Atoi(parts[2])
		if e != nil {
			return true, "", errors.New("套餐天数须为整数")
		}
		uses, e := strconv.Atoi(parts[3])
		if e != nil {
			return true, "", errors.New("可用次数须为整数")
		}
		_, result, e := a.membershipAction(ctx, user, actionInput{Action: "membership.code.create", Params: map[string]any{"planId": parts[1], "days": days, "maxUses": uses, "count": 1, "expires": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)}})
		if e != nil {
			return true, "", e
		}
		return true, fmt.Sprint(result["codes"]) + "\n兑换截止时间为24小时后。", nil
	}
	return false, "", nil
}

func (a *App) subscriptionExpiryEvents(ctx context.Context, now time.Time) {
	rows, e := a.DB.ListRecords(ctx, "subscriptions", "")
	if e != nil {
		return
	}
	for _, sub := range rows {
		if disabledStatus(sub.Data) {
			continue
		}
		expiry := dateTime(text(sub.Data, "expires"))
		remaining := expiry.Sub(now)
		days := 0
		switch {
		case remaining > 0 && remaining <= 24*time.Hour:
			days = 1
		case remaining > 48*time.Hour && remaining <= 72*time.Hour:
			days = 3
		case remaining > 6*24*time.Hour && remaining <= 7*24*time.Hour:
			days = 7
		}
		if days == 0 {
			continue
		}
		key := sub.ID + "/" + expiry.UTC().Format(time.RFC3339) + "/" + strconv.Itoa(days)
		a.emitEvent(ctx, "subscription.expiring", sub.OwnerID, key, fmt.Sprintf("套餐 %s 将在%d天内到期（%s）。续费后可发送 /renew %s 提交核对。", text(sub.Data, "name"), days, expiry.Format("2006-01-02 15:04 MST"), sub.ID), map[string]any{"subscriptionId": sub.ID, "days": days, "expires": expiry})
	}
}

func (a *App) allowTelegramCommand(chat string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := "telegram:" + chat
	window := a.limits[key]
	if window == nil || time.Since(window.Start) > time.Minute {
		window = &rateWindow{Start: time.Now()}
		a.limits[key] = window
	}
	window.Count++
	return window.Count <= 20
}
