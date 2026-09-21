package httpapi

import (
	"context"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/url"
	"strings"
	"time"
)

func (a *App) telegramControl(ctx context.Context, actor store.User, action string) (map[string]any, error) {
	var settings map[string]any
	_ = a.DB.GetSetting(ctx, "settings", &settings)
	token := text(settings, "telegramToken")
	if token == "" || strings.ContainsAny(token, "/?# ") {
		return nil, errors.New("请先配置有效 Telegram Bot Token")
	}
	method := "getWebhookInfo"
	params := map[string]any{}
	switch action {
	case "telegram.webhook.set":
		endpoint := strings.TrimRight(a.Config.PublicURL, "/") + "/api/telegram/webhook"
		u, e := url.Parse(endpoint)
		if e != nil || u.Scheme != "https" {
			return nil, errors.New("Telegram Webhook需要可从公网访问的HTTPS主控地址")
		}
		secret := text(settings, "telegramWebhookSecret")
		if secret == "" {
			secret = newID() + newID()
			settings["telegramWebhookSecret"] = secret
			if e = a.DB.SetSetting(ctx, "settings", settings); e != nil {
				return nil, e
			}
		}
		params = map[string]any{"url": endpoint, "secret_token": secret, "allowed_updates": []string{"message"}, "drop_pending_updates": false}
		method = "setWebhook"
	case "telegram.webhook.delete":
		method = "deleteWebhook"
		params["drop_pending_updates"] = false
	case "telegram.commands.set":
		method = "setMyCommands"
		params["commands"] = []map[string]string{{"command": "help", "description": "查看帮助"}, {"command": "me", "description": "我的账户"}, {"command": "usage", "description": "套餐用量"}, {"command": "subscriptions", "description": "我的订阅"}, {"command": "servers", "description": "管理员服务器状态"}, {"command": "tasks", "description": "管理员任务状态"}}
	case "telegram.webhook.status":
	default:
		return nil, errors.New("未知Telegram控制动作")
	}
	var result struct {
		OK     bool `json:"ok"`
		Result any  `json:"result"`
	}
	if e := a.externalJSON(ctx, "POST", "https://api.telegram.org/bot"+token+"/"+method, nil, params, &result); e != nil {
		return nil, e
	}
	if !result.OK {
		return nil, errors.New("Telegram拒绝该操作")
	}
	a.audit(ctx, actor, action, "telegram", nil)
	return map[string]any{"success": true, "result": result.Result}, nil
}
func (a *App) telegramAdminCommand(ctx context.Context, user store.User, parts []string) (string, error) {
	if user.Role != "admin" {
		return "", errors.New("需要管理员权限")
	}
	if parts[0] == "/confirm" {
		if len(parts) != 2 {
			return "", errors.New("使用 /confirm 确认码")
		}
		pending, e := a.DB.GetRecord(ctx, "_telegramConfirmations", hashOpaque(parts[1]))
		if e != nil || pending.OwnerID != user.ID || boolean(pending.Data, "used") || number(pending.Data, "expiresAt") < float64(time.Now().Unix()) {
			return "", errors.New("确认已过期或已使用")
		}
		pending.Data["used"] = true
		if _, e = a.DB.SaveRecord(ctx, pending); e != nil {
			return "", errors.New("确认已被使用")
		}
		task, e := a.queue(ctx, user, text(pending.Data, "serverId"), text(pending.Data, "action"), nil)
		if e != nil {
			return "", e
		}
		return "已建立任务 " + task.ID + "，使用 /tasks 查看实际结果。", nil
	}
	if len(parts) != 2 {
		return "", errors.New("使用 /restart 服务器ID 或 /stop 服务器ID")
	}
	if _, e := a.DB.GetRecord(ctx, "servers", parts[1]); e != nil {
		return "", errors.New("服务器不存在")
	}
	action := "core.restart"
	if parts[0] == "/stop" {
		action = "core.stop"
	}
	code := newID()
	_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_telegramConfirmations", ID: hashOpaque(code), OwnerID: user.ID, Data: map[string]any{"serverId": parts[1], "action": action, "expiresAt": time.Now().Add(time.Minute).Unix()}})
	if e != nil {
		return "", e
	}
	return "即将执行 " + action + "。一分钟内发送 /confirm " + code + " 确认。", nil
}
