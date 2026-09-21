package httpapi

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) registerTelegram(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/telegram/webhook", a.telegramWebhook)
	mux.HandleFunc("POST /api/telegram/miniapp", a.telegramMiniApp)
	mux.HandleFunc("POST /api/account/telegram", a.withUser(a.telegramBinding))
}
func (a *App) telegramBinding(w http.ResponseWriter, r *http.Request) {
	var in struct{ Unbind bool }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if in.Unbind {
		bindings, e := a.DB.ListRecords(r.Context(), "_telegramBindings", u.ID)
		if e != nil {
			fail(w, 500, "storage_error", "解绑失败")
			return
		}
		for _, binding := range bindings {
			if e = a.DB.DeleteRecord(r.Context(), "_telegramBindings", binding.ID); e != nil {
				fail(w, 500, "storage_error", "解绑失败")
				return
			}
		}
		respond(w, 200, map[string]bool{"success": true})
		return
	}
	code := newID()
	hash := hashOpaque(code)
	_, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: "_telegramBindCodes", ID: hash, OwnerID: u.ID, Data: map[string]any{"expires": time.Now().Add(5 * time.Minute).Unix(), "tokenVersion": u.TokenVersion}})
	if e != nil {
		fail(w, 500, "storage_error", "无法创建绑定码")
		return
	}
	respond(w, 200, map[string]any{"code": code, "command": "/bind " + code, "expiresIn": 300})
}
func (a *App) telegramWebhook(w http.ResponseWriter, r *http.Request) {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	secret := text(settings, "telegramWebhookSecret")
	if secret == "" || !constant(secret, r.Header.Get("X-Telegram-Bot-Api-Secret-Token")) {
		fail(w, 403, "forbidden", "Webhook认证失败")
		return
	}
	var update struct {
		ID      int64 `json:"update_id"`
		Message struct {
			ID   int64  `json:"message_id"`
			Text string `json:"text"`
			From struct {
				ID int64 `json:"id"`
			} `json:"from"`
			Chat struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	}
	if !decode(w, r, &update) {
		return
	}
	if update.ID <= 0 || update.Message.Chat.Type != "private" || update.Message.From.ID != update.Message.Chat.ID {
		respond(w, 200, map[string]bool{"ok": true})
		return
	}
	id := strconv.FormatInt(update.ID, 10)
	if _, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: "_telegramUpdates", ID: id, Data: map[string]any{"receivedAt": time.Now().Unix()}}); errors.Is(e, store.ErrConflict) {
		respond(w, 200, map[string]bool{"ok": true})
		return
	} else if e != nil {
		fail(w, 500, "storage_error", "无法记录通知")
		return
	}
	chat := strconv.FormatInt(update.Message.Chat.ID, 10)
	message, e := a.telegramCommand(r.Context(), chat, update.Message.Text)
	if e != nil {
		message = e.Error()
	}
	_, e = a.notificationTest(r.Context(), store.User{ID: "telegram", Role: "user"}, "", map[string]any{"channel": "telegram", "chatId": chat, "message": message})
	if e != nil {
		_, _ = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_telegramDeliveryFailures", ID: id, Data: map[string]any{"error": e.Error(), "at": time.Now().UTC()}})
	}
	respond(w, 200, map[string]bool{"ok": true})
}
func (a *App) telegramCommand(ctx context.Context, chat, command string) (string, error) {
	if !a.allowTelegramCommand(chat) {
		return "", errors.New("命令过于频繁，请稍后再试")
	}
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "使用 /help 查看可用命令", nil
	}
	name := strings.Split(parts[0], "@")[0]
	if name == "/bind" {
		if len(parts) != 2 {
			return "", errors.New("请在网站账户页创建绑定码，再发送 /bind 绑定码")
		}
		code, e := a.DB.GetRecord(ctx, "_telegramBindCodes", hashOpaque(parts[1]))
		if e != nil || boolean(code.Data, "used") || number(code.Data, "expires") < float64(time.Now().Unix()) {
			return "", errors.New("绑定码无效或已过期")
		}
		user, e := a.DB.UserByID(ctx, code.OwnerID)
		if e != nil || user.Disabled || user.TokenVersion != int64(number(code.Data, "tokenVersion")) {
			return "", errors.New("账户状态已变更")
		}
		bindings, e := a.DB.ListRecords(ctx, "_telegramBindings", "")
		if e != nil {
			return "", e
		}
		for _, binding := range bindings {
			if text(binding.Data, "chatId") == chat && binding.OwnerID != user.ID {
				return "", errors.New("此Telegram账户已绑定其他用户")
			}
		}
		old, _ := a.DB.GetRecord(ctx, "_telegramBindings", chat)
		code.Data["used"] = true
		_, e = a.DB.CompareAndSaveRecords(ctx, []store.Record{code, {Collection: "_telegramBindings", ID: chat, OwnerID: user.ID, Version: old.Version, Data: map[string]any{"chatId": chat, "boundAt": time.Now().UTC()}}})
		if e != nil {
			return "", errors.New("绑定码已使用，请重新创建")
		}
		return "已绑定 ASWired 账户 " + user.Username, nil
	}
	bindings, e := a.DB.ListRecords(ctx, "_telegramBindings", "")
	if e != nil {
		return "", e
	}
	var user store.User
	for _, binding := range bindings {
		if text(binding.Data, "chatId") == chat {
			user, e = a.DB.UserByID(ctx, binding.OwnerID)
			break
		}
	}
	if user.ID == "" || e != nil || user.Disabled {
		return "", errors.New("请先在 ASWired 网站账户页绑定 Telegram")
	}
	parts[0] = name
	if handled, message, e := a.telegramExtraCommand(ctx, user, chat, parts); handled {
		return message, e
	}
	if name == "/restart" || name == "/stop" || name == "/confirm" {
		parts[0] = name
		return a.telegramAdminCommand(ctx, user, parts)
	}
	switch name {
	case "/help", "/start":
		return "/me 查看账户\n/usage 查看套餐用量\n/subscriptions 查看订阅\n/nodes 查看节点\n/notify on|off 事件通知\n/renew 套餐订阅ID 提交续费声明\n/redeem 兑换码\n/unbind 确认解绑\n管理员：/servers /tasks /restart /stop /find /codescreate /codesrevoke /requests", nil
	case "/me":
		return "ASWired · " + user.Username + " (" + user.Role + ")", nil
	case "/usage", "/subscriptions":
		subs, e := a.DB.ListRecords(ctx, "subscriptions", user.ID)
		if e != nil {
			return "", e
		}
		lines := []string{}
		for _, sub := range subs {
			line := fmt.Sprintf("%s：%.2f / %.2f GiB · %s", text(sub.Data, "name"), number(sub.Data, "used"), number(sub.Data, "limit"), text(sub.Data, "effectiveStatus")) + "\nID: " + sub.ID
			if name == "/subscriptions" && a.subscriptionActive(ctx, sub) == nil {
				line += "\n" + strings.TrimRight(a.Config.PublicURL, "/") + "/api/clash/subscribe?token=" + url.QueryEscape(text(sub.Data, "token"))
			}
			lines = append(lines, line)
		}
		if len(lines) == 0 {
			return "暂无已分配套餐", nil
		}
		return strings.Join(lines, "\n\n"), nil
	case "/servers":
		if user.Role != "admin" {
			return "", errors.New("需要管理员权限")
		}
		servers, e := a.DB.ListRecords(ctx, "servers", "")
		if e != nil {
			return "", e
		}
		lines := []string{}
		for _, server := range servers {
			a.mu.Lock()
			peer := a.peers[server.ID]
			online := peer != nil && time.Since(peer.LastSeen) < 45*time.Second
			a.mu.Unlock()
			lines = append(lines, fmt.Sprintf("%s · 在线=%t", text(server.Data, "name"), online))
		}
		return strings.Join(lines, "\n"), nil
	case "/tasks":
		if user.Role != "admin" {
			return "", errors.New("需要管理员权限")
		}
		tasks, e := a.DB.ListTasks(ctx, "", 10)
		if e != nil {
			return "", e
		}
		lines := []string{}
		for _, task := range tasks {
			lines = append(lines, task.Kind+" · "+task.Status)
		}
		return strings.Join(lines, "\n"), nil
	}
	return "未知命令，使用 /help 查看帮助", nil
}
func verifyTelegramInit(raw, token string, now time.Time) (string, error) {
	values, e := url.ParseQuery(raw)
	if e != nil {
		return "", e
	}
	provided := values.Get("hash")
	values.Del("hash")
	keys := []string{}
	for key, v := range values {
		if len(v) != 1 {
			return "", errors.New("duplicate Mini App field")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := []string{}
	for _, key := range keys {
		lines = append(lines, key+"="+values.Get(key))
	}
	key := hmacSHA256([]byte("WebAppData"), token)
	digest := hmacSHA256(key, strings.Join(lines, "\n"))
	expected, e := hex.DecodeString(provided)
	if e != nil || !hmac.Equal(expected, digest) {
		return "", errors.New("Mini App签名无效")
	}
	timestamp, e := strconv.ParseInt(values.Get("auth_date"), 10, 64)
	if e != nil || timestamp > now.Add(time.Minute).Unix() || timestamp < now.Add(-5*time.Minute).Unix() {
		return "", errors.New("Mini App登录已过期")
	}
	var user struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal([]byte(values.Get("user")), &user) != nil || user.ID == 0 {
		return "", errors.New("Mini App用户无效")
	}
	return strconv.FormatInt(user.ID, 10), nil
}
func (a *App) telegramMiniApp(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁")
		return
	}
	var in struct {
		InitData string `json:"initData"`
	}
	if !decode(w, r, &in) {
		return
	}
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	token := text(settings, "telegramToken")
	if token == "" || !boolean(settings, "telegramMiniAppEnabled") {
		fail(w, 404, "not_found", "Mini App未启用")
		return
	}
	chat, e := verifyTelegramInit(in.InitData, token, time.Now())
	if e != nil {
		fail(w, 401, "invalid_telegram", e.Error())
		return
	}
	bindings, e := a.DB.ListRecords(r.Context(), "_telegramBindings", "")
	if e != nil {
		fail(w, 500, "storage_error", "无法读取绑定")
		return
	}
	for _, binding := range bindings {
		if text(binding.Data, "chatId") == chat {
			user, e := a.DB.UserByID(r.Context(), binding.OwnerID)
			if e != nil || user.Disabled {
				break
			}
			a.issue(w, user)
			return
		}
	}
	fail(w, 403, "not_bound", "请先通过网站绑定Telegram账户")
}
