package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var memberLinkMu sync.Mutex
var memberCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{24,128}$`)

func (a *App) registerMemberManagement(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/members/management", a.withAdmin(a.memberManagement))
	mux.HandleFunc("PUT /api/members/{id}", a.withAdmin(a.memberUpdate))
	mux.HandleFunc("DELETE /api/members/{id}", a.withAdmin(a.memberDelete))
	mux.HandleFunc("POST /api/members/{id}/subscription-link", a.withAdmin(a.memberSubscriptionLink))
	mux.HandleFunc("POST /api/members/{id}/telegram", a.withAdmin(a.memberTelegram))
}

func mergedMemberCode(rec store.Record) string {
	u, err := url.Parse(text(rec.Data, "url"))
	if err != nil {
		return ""
	}
	code := u.Query().Get("token")
	if membershipHash(code) != text(rec.Data, "tokenHash") || !memberCodePattern.MatchString(code) {
		return ""
	}
	return code
}

func (a *App) memberManagement(w http.ResponseWriter, r *http.Request) {
	users, err := a.DB.ListUsers(r.Context())
	if err != nil {
		fail(w, 500, "storage_error", "读取用户失败")
		return
	}
	collections := map[string][]store.Record{}
	for _, name := range []string{"members", "subscriptions", "_telegramBindings", "_mergedSubscriptions"} {
		rows, err := a.DB.ListRecords(r.Context(), name, "")
		if err != nil {
			fail(w, 500, "storage_error", "读取用户资料失败")
			return
		}
		collections[name] = rows
	}
	profiles := map[string]store.Record{}
	for _, rec := range collections["members"] {
		profiles[rec.ID] = rec
	}
	links := map[string]store.Record{}
	for _, rec := range collections["_mergedSubscriptions"] {
		links[rec.OwnerID] = rec
	}
	telegram := map[string][]map[string]any{}
	for _, rec := range collections["_telegramBindings"] {
		telegram[rec.OwnerID] = append(telegram[rec.OwnerID], map[string]any{"chatId": text(rec.Data, "chatId"), "boundAt": rec.Data["boundAt"]})
	}
	subscriptions := map[string][]map[string]any{}
	for _, rec := range collections["subscriptions"] {
		row := map[string]any{"id": rec.ID, "name": text(rec.Data, "name"), "planId": text(rec.Data, "planId"), "plan": text(rec.Data, "plan"), "limit": number(rec.Data, "limit"), "expires": text(rec.Data, "expires"), "cycleEnd": text(rec.Data, "cycleEnd"), "status": text(rec.Data, "status"), "recordVersion": rec.Version}
		used, _, _, err := a.subscriptionUsage(r.Context(), rec)
		if err != nil {
			row["used"] = nil
			row["usageUnavailable"] = true
		} else {
			row["used"] = used / gib
		}
		subscriptions[rec.OwnerID] = append(subscriptions[rec.OwnerID], row)
	}
	rows := []map[string]any{}
	for _, u := range users {
		profile := profiles[u.ID]
		row := map[string]any{"id": u.ID, "username": u.Username, "name": defaultText(profile.Data, "name", u.Username), "email": text(profile.Data, "email"), "note": text(profile.Data, "note"), "role": map[bool]string{true: "管理员", false: "普通用户"}[u.Role == "admin"], "status": map[bool]string{true: "暂停", false: "正常"}[u.Disabled], "application": defaultText(profile.Data, "application", "aswired"), "recordVersion": profile.Version, "behaviorLimits": profile.Data["behaviorLimits"], "resourceQuotas": profile.Data["resourceQuotas"], "telegram": telegram[u.ID], "subscriptions": subscriptions[u.ID], "createdAt": u.CreatedAt}
		if link, ok := links[u.ID]; ok && boolean(link.Data, "enabled") {
			row["shortCode"] = mergedMemberCode(link)
		}
		rows = append(rows, row)
	}
	respond(w, 200, map[string]any{"rows": rows})
}

func (a *App) memberUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Row map[string]any `json:"row"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := a.DB.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "用户不存在")
		return
	}
	previous, err := a.DB.GetRecord(r.Context(), "members", u.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, 500, "storage_error", "读取用户资料失败")
		return
	}
	if in.Row == nil || int64(number(in.Row, "recordVersion")) != previous.Version {
		fail(w, 409, "conflict", "用户资料已更新，请刷新后重试")
		return
	}
	row := clone(previous.Data)
	if row == nil {
		row = map[string]any{}
	}
	row["name"] = defaultText(row, "name", u.Username)
	row["username"] = u.Username
	row["role"] = u.Role
	row["status"] = map[bool]string{true: "暂停", false: "正常"}[u.Disabled]
	for _, key := range []string{"name", "username", "email", "note", "role", "status", "application", "password", "behaviorLimits", "resourceQuotas"} {
		if value, ok := in.Row[key]; ok {
			row[key] = value
		}
	}
	if strings.TrimSpace(text(row, "name")) == "" || len(text(row, "name")) > 128 || len(text(row, "note")) > 2000 || len(text(row, "email")) > 320 {
		fail(w, 400, "invalid_member", "请填写昵称；昵称至多 128 字符，备注至多 2000 字符")
		return
	}
	if err = validateLimitConfiguration(row); err != nil {
		fail(w, 400, "invalid_limits", err.Error())
		return
	}
	prepared, err := a.prepareMember(r, u.ID, row, true)
	if err != nil {
		fail(w, 400, "invalid_member", err.Error())
		return
	}
	saved, err := a.DB.SaveMemberRecord(r.Context(), prepared, store.Record{Collection: "members", ID: u.ID, OwnerID: u.ID, Data: row, Version: previous.Version}, true)
	if err != nil {
		fail(w, 409, "conflict", "账户已更新或操作冲突，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "member.update", u.ID, nil)
	a.reconcileUsers(r.Context(), current(r))
	respond(w, 200, map[string]any{"row": rowOf(saved, false)})
}

func (a *App) memberDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.Confirm {
		fail(w, 400, "confirmation_required", "请确认删除用户及关联资料")
		return
	}
	id := r.PathValue("id")
	if id == current(r).ID {
		fail(w, 409, "self_delete", "不能删除当前登录账户")
		return
	}
	if err := a.DB.DeleteMember(r.Context(), id); err != nil {
		fail(w, 409, "member_delete_failed", "用户不存在或不能删除最后一个管理员")
		return
	}
	a.audit(r.Context(), current(r), "member.delete", id, nil)
	a.reconcileUsers(r.Context(), current(r))
	respond(w, 200, map[string]bool{"success": true})
}

func (a *App) memberSubscriptionLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code    string `json:"code"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := a.DB.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "用户不存在")
		return
	}
	if u.Disabled {
		fail(w, 400, "member_disabled", "用户已停用")
		return
	}
	subscriptions, err := a.DB.ListRecords(r.Context(), "subscriptions", u.ID)
	if err != nil || len(subscriptions) == 0 {
		fail(w, 400, "no_subscriptions", "请先为用户绑定套餐")
		return
	}
	if in.Code != "" && (!in.Confirm || !memberCodePattern.MatchString(in.Code)) {
		fail(w, 400, "invalid_code", "请确认修改；短码须为 24–128 位字母、数字、下划线或横线")
		return
	}
	memberLinkMu.Lock()
	defer memberLinkMu.Unlock()
	rec, err := a.DB.GetRecord(r.Context(), "_mergedSubscriptions", u.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, 500, "storage_error", "读取用户订阅失败")
		return
	}
	if rec.Data == nil {
		rec = store.Record{Collection: "_mergedSubscriptions", ID: u.ID, OwnerID: u.ID, Data: map[string]any{}}
	}
	code := in.Code
	if code == "" {
		code = mergedMemberCode(rec)
	}
	if code == "" {
		code = newID() + newID()
	}
	records, err := a.DB.ListRecords(r.Context(), "_mergedSubscriptions", "")
	if err != nil {
		fail(w, 500, "storage_error", "读取订阅失败")
		return
	}
	for _, other := range records {
		if other.OwnerID != u.ID && text(other.Data, "tokenHash") == membershipHash(code) {
			fail(w, 409, "code_in_use", "该短码已被使用")
			return
		}
	}
	rec.Data["enabled"] = true
	rec.Data["tokenHash"] = membershipHash(code)
	rec.Data["url"] = strings.TrimRight(a.Config.PublicURL, "/") + "/api/merged-subscribe?token=" + url.QueryEscape(code)
	if _, err = a.DB.SaveRecord(r.Context(), rec); err != nil {
		fail(w, 409, "conflict", "订阅已变更，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "member.subscription.update", u.ID, nil)
	respond(w, 200, map[string]any{"url": rec.Data["url"], "shortCode": code})
}

func (a *App) memberTelegram(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Unbind  bool `json:"unbind"`
		Confirm bool `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := a.DB.UserByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "用户不存在")
		return
	}
	if in.Unbind {
		if !in.Confirm {
			fail(w, 400, "confirmation_required", "请确认解绑 Telegram")
			return
		}
		records, err := a.DB.ListRecords(r.Context(), "_telegramBindings", u.ID)
		if err != nil {
			fail(w, 500, "storage_error", "读取绑定失败")
			return
		}
		for _, rec := range records {
			if err = a.DB.ConsumeRecord(r.Context(), rec); err != nil {
				fail(w, 409, "conflict", "绑定已更新，请重试")
				return
			}
		}
		a.audit(r.Context(), current(r), "member.telegram.unbind", u.ID, nil)
		respond(w, 200, map[string]bool{"success": true})
		return
	}
	if u.Disabled {
		fail(w, 400, "member_disabled", "停用用户不能绑定 Telegram")
		return
	}
	code := newID()
	if _, err = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_telegramBindCodes", ID: hashOpaque(code), OwnerID: u.ID, Data: map[string]any{"expires": time.Now().Add(5 * time.Minute).Unix(), "tokenVersion": u.TokenVersion}}); err != nil {
		fail(w, 500, "storage_error", "生成绑定码失败")
		return
	}
	a.audit(r.Context(), current(r), "member.telegram.code", u.ID, nil)
	respond(w, 200, map[string]any{"command": "/bind " + code, "expiresIn": 300})
}
