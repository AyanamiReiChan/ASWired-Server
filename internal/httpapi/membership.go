package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) registerMembership(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/membership", a.withUser(a.membershipView))
	mux.HandleFunc("GET /api/account/merged-subscription", a.withUser(a.mergedView))
	mux.HandleFunc("PUT /api/account/merged-subscription", a.withUser(a.mergedSave))
	mux.HandleFunc("GET /api/merged-subscribe", a.mergedDownload)
}
func membershipHash(raw string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(h[:])
}
func (a *App) membershipAction(ctx context.Context, u store.User, in actionInput) (bool, map[string]any, error) {
	var result map[string]any
	var err error
	switch in.Action {
	case "membership.code.create":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可创建兑换码")
		}
		result, err = a.membershipCodes(ctx, u, in.Params)
	case "membership.code.revoke":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可吊销兑换码")
		}
		var rec store.Record
		rec, err = a.DB.GetRecord(ctx, "_membershipCodes", in.TargetID)
		if err == nil {
			rec.Data["revoked"] = true
			_, err = a.DB.SaveRecord(ctx, rec)
			result = map[string]any{"success": err == nil}
		}
	case "membership.redeem":
		result, err = a.membershipRedeem(ctx, u, text(in.Params, "code"))
	case "membership.request":
		result, err = a.membershipRequest(ctx, u, in.TargetID, text(in.Params, "note"))
	case "membership.request.confirm", "membership.request.reject":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可核对申请")
		}
		result, err = a.membershipConfirmRequest(ctx, u, in)
	case "subscription.renewal.declare":
		result, err = a.membershipDeclare(ctx, u, in.TargetID, text(in.Params, "note"))
	case "subscription.renewal.batch":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可批量核对")
		}
		entries, ok := in.Params["entries"].([]any)
		if !ok || len(entries) < 1 || len(entries) > 100 {
			return true, nil, errors.New("一次核对1至100个续期声明")
		}
		results := []map[string]any{}
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				return true, nil, errors.New("续期列表格式无效")
			}
			p := clone(in.Params)
			p["recordVersion"] = entry["recordVersion"]
			value, e := a.membershipConfirmRenewal(ctx, u, actionInput{Action: "subscription.renewal.confirm", TargetID: text(entry, "id"), Params: p})
			if e != nil {
				results = append(results, map[string]any{"id": entry["id"], "success": false, "error": e.Error()})
			} else {
				value["id"] = entry["id"]
				results = append(results, value)
			}
		}
		result = map[string]any{"results": results}
	case "subscription.traffic.reset":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可重置套餐用量")
		}
		result, err = a.membershipResetTraffic(ctx, u, in)
	case "subscription.renewal.confirm", "subscription.renewal.reject":
		if u.Role != "admin" {
			return true, nil, errors.New("仅管理员可核对续期")
		}
		result, err = a.membershipConfirmRenewal(ctx, u, in)
	default:
		return false, nil, nil
	}
	if err == nil {
		a.audit(ctx, u, in.Action, in.TargetID, nil)
	}
	return true, result, err
}
func (a *App) membershipView(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	plans := []map[string]any{}
	recs, e := a.DB.ListRecords(r.Context(), "plans", "")
	if e != nil {
		fail(w, 500, "storage_error", "读取套餐失败")
		return
	}
	for _, p := range recs {
		if !disabledStatus(p.Data) && boolean(p.Data, "selfService") {
			plans = append(plans, map[string]any{"id": p.ID, "name": p.Data["name"], "description": p.Data["description"], "price": p.Data["price"], "cycleDays": p.Data["cycleDays"], "limit": p.Data["limit"], "speed": p.Data["speed"], "ipLimit": p.Data["ipLimit"], "instructions": p.Data["instructions"]})
		}
	}
	out := map[string]any{"plans": plans}
	owner := u.ID
	if u.Role == "admin" {
		owner = ""
	}
	for key, col := range map[string]string{"requests": "_membershipRequests", "renewals": "_renewalDeclarations", "history": "_renewalHistory"} {
		rows, err := a.DB.ListRecords(r.Context(), col, owner)
		if err != nil {
			fail(w, 500, "storage_error", "读取记录失败")
			return
		}
		items := []map[string]any{}
		for _, rec := range rows {
			items = append(items, rowOf(rec, false))
		}
		out[key] = items
	}
	if u.Role == "admin" {
		codes, err := a.DB.ListRecords(r.Context(), "_membershipCodes", "")
		if err != nil {
			fail(w, 500, "storage_error", "读取兑换码失败")
			return
		}
		items := []map[string]any{}
		for _, rec := range codes {
			items = append(items, map[string]any{"id": rec.ID, "planId": rec.Data["planId"], "plan": rec.Data["plan"], "label": rec.Data["label"], "days": rec.Data["days"], "maxUses": rec.Data["maxUses"], "used": rec.Data["used"], "expires": rec.Data["expires"], "revoked": rec.Data["revoked"], "createdAt": rec.CreatedAt})
		}
		out["codes"] = items
	}
	respond(w, 200, out)
}
func (a *App) membershipCodes(ctx context.Context, u store.User, p map[string]any) (map[string]any, error) {
	plan, err := a.DB.GetRecord(ctx, "plans", text(p, "planId"))
	if err != nil || disabledStatus(plan.Data) {
		return nil, errors.New("请选择已启用的套餐")
	}
	count, uses, days := int(number(p, "count")), int(number(p, "maxUses")), int(number(p, "days"))
	if count < 1 || count > 100 || uses < 1 || uses > 10000 || days < 0 || days > 3660 {
		return nil, errors.New("数量为1–100，次数为1–10000，套餐天数为0–3660（0为长期）")
	}
	expires := text(p, "expires")
	if expires != "" {
		t := dateTime(expires)
		if t.IsZero() || !time.Now().Before(t) {
			return nil, errors.New("兑换截止时间必须在未来")
		}
	}
	records := []store.Record{}
	out := []map[string]any{}
	for i := 0; i < count; i++ {
		code := newID() + newID()
		id := membershipHash(code)
		records = append(records, store.Record{Collection: "_membershipCodes", ID: id, OwnerID: u.ID, Data: map[string]any{"planId": plan.ID, "plan": text(plan.Data, "name"), "label": text(p, "label"), "days": days, "maxUses": uses, "used": 0, "expires": expires, "revoked": false, "redemptions": map[string]any{}}})
		out = append(out, map[string]any{"id": id, "code": code, "url": strings.TrimRight(a.Config.PublicURL, "/") + "/join?code=" + url.QueryEscape(code)})
	}
	if _, err = a.DB.CompareAndSaveRecords(ctx, records); err != nil {
		return nil, err
	}
	return map[string]any{"codes": out, "message": "兑换码仅在此时显示，请妥善保存"}, nil
}
func (a *App) membershipNewSubscription(ctx context.Context, u store.User, planID string, days int) (store.Record, error) {
	id := newID()
	data := map[string]any{"memberId": u.ID, "planId": planID, "name": u.Username + " · 套餐", "status": "启用"}
	if days > 0 {
		data["expires"] = time.Now().UTC().AddDate(0, 0, days).Format(time.RFC3339)
	}
	r := (&http.Request{}).WithContext(ctx)
	owner, err := a.prepareSubscription(r, id, data, false)
	if err != nil {
		return store.Record{}, err
	}
	data["name"] = u.Username + " · " + text(data, "plan")
	return store.Record{Collection: "subscriptions", ID: id, OwnerID: owner, Data: data}, nil
}
func (a *App) membershipRedeem(ctx context.Context, u store.User, code string) (map[string]any, error) {
	if len(code) < 24 || len(code) > 200 {
		return nil, errors.New("兑换码无效")
	}
	id := membershipHash(code)
	for retry := 0; retry < 8; retry++ {
		rec, err := a.DB.GetRecord(ctx, "_membershipCodes", id)
		if err != nil {
			return nil, errors.New("兑换码无效")
		}
		used, _ := rec.Data["redemptions"].(map[string]any)

		if boolean(rec.Data, "revoked") {
			return nil, errors.New("兑换码已吊销")
		}
		if exp := dateTime(text(rec.Data, "expires")); !exp.IsZero() && !time.Now().Before(exp) {
			return nil, errors.New("兑换码已过期")
		}
		if previous, ok := used[u.ID].(string); ok && previous != "" {
			return map[string]any{"success": true, "subscriptionId": previous, "alreadyRedeemed": true}, nil
		}
		if number(rec.Data, "used") >= number(rec.Data, "maxUses") {
			return nil, errors.New("兑换次数已用尽")
		}
		existing, err := a.DB.ListRecords(ctx, "subscriptions", u.ID)
		if err != nil {
			return nil, err
		}
		for _, s := range existing {
			if text(s.Data, "planId") == text(rec.Data, "planId") {
				return nil, errors.New("已持有该套餐，请在原实例办理续期；兑换次数未扣除")
			}
		}
		sub, err := a.membershipNewSubscription(ctx, u, text(rec.Data, "planId"), int(number(rec.Data, "days")))
		if err != nil {
			return nil, err
		}
		next := map[string]any{}
		for k, v := range used {
			next[k] = v
		}
		next[u.ID] = sub.ID
		rec.Data["redemptions"] = next
		rec.Data["used"] = number(rec.Data, "used") + 1
		if _, err = a.DB.CompareAndSaveRecords(ctx, []store.Record{rec, sub}); errors.Is(err, store.ErrConflict) {
			continue
		} else if err != nil {
			return nil, err
		}
		a.reconcileUsers(ctx, u)
		return map[string]any{"success": true, "subscriptionId": sub.ID}, nil
	}
	return nil, errors.New("兑换状态正在更新，请重试")
}
func (a *App) membershipRequest(ctx context.Context, u store.User, planID, note string) (map[string]any, error) {
	p, err := a.DB.GetRecord(ctx, "plans", planID)
	if err != nil || disabledStatus(p.Data) || !boolean(p.Data, "selfService") {
		return nil, errors.New("该套餐未开放成员申请")
	}
	if len(note) > 1000 {
		return nil, errors.New("备注不能超过1000字节")
	}
	subscriptions, err := a.DB.ListRecords(ctx, "subscriptions", u.ID)
	if err != nil {
		return nil, err
	}
	for _, sub := range subscriptions {
		if text(sub.Data, "planId") == planID {
			return nil, errors.New("已持有该套餐，请在原实例办理续期")
		}
	}
	id := membershipHash(u.ID + ":" + planID)
	rec, err := a.DB.GetRecord(ctx, "_membershipRequests", id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err == nil && text(rec.Data, "status") == "待核对" {
		return map[string]any{"success": true, "requestId": id, "alreadyPending": true}, nil
	}
	rec.Collection = "_membershipRequests"
	rec.ID = id
	rec.OwnerID = u.ID
	rec.Data = map[string]any{"member": u.Username, "planId": planID, "plan": text(p.Data, "name"), "price": number(p.Data, "price"), "note": note, "status": "待核对", "requestedAt": time.Now().UTC().Format(time.RFC3339)}
	_, err = a.DB.SaveRecord(ctx, rec)
	return map[string]any{"success": err == nil, "requestId": id, "message": "申请已提交，管理员核对后发放；本操作未收款"}, err
}
func (a *App) membershipConfirmRequest(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	rec, err := a.DB.GetRecord(ctx, "_membershipRequests", in.TargetID)
	if err != nil {
		return nil, err
	}
	if text(rec.Data, "status") != "待核对" {
		return map[string]any{"success": true, "alreadyProcessed": true}, nil
	}
	if int64(number(in.Params, "recordVersion")) != rec.Version {
		return nil, errors.New("申请已更新，请刷新后重新核对")
	}
	rec.Data["reviewedBy"] = u.ID
	rec.Data["reviewedAt"] = time.Now().UTC().Format(time.RFC3339)
	rec.Data["reviewNote"] = text(in.Params, "note")
	if in.Action == "membership.request.reject" {
		rec.Data["status"] = "已拒绝"
		_, err = a.DB.SaveRecord(ctx, rec)
		return map[string]any{"success": err == nil}, err
	}
	if !boolean(in.Params, "confirmed") {
		return nil, errors.New("请先确认已人工核对发放条件")
	}
	days := int(number(in.Params, "days"))
	if days < 0 || days > 3660 {
		return nil, errors.New("套餐天数为0–3660，0表示长期")
	}
	member, err := a.DB.UserByID(ctx, rec.OwnerID)
	if err != nil || member.Disabled {
		return nil, errors.New("成员不可用")
	}
	sub, err := a.membershipNewSubscription(ctx, member, text(rec.Data, "planId"), days)
	if err != nil {
		return nil, err
	}
	rec.Data["status"] = "已发放"
	rec.Data["subscriptionId"] = sub.ID
	_, err = a.DB.CompareAndSaveRecords(ctx, []store.Record{rec, sub})
	if err == nil {
		a.reconcileUsers(ctx, u)
	}
	return map[string]any{"success": err == nil, "subscriptionId": sub.ID}, err
}
func (a *App) membershipDeclare(ctx context.Context, u store.User, id, note string) (map[string]any, error) {
	sub, err := a.DB.GetRecord(ctx, "subscriptions", id)
	if err != nil {
		return nil, err
	}
	if u.Role != "admin" && sub.OwnerID != u.ID {
		return nil, errors.New("不能操作他人的套餐")
	}
	if len(note) > 1000 {
		return nil, errors.New("备注不能超过1000字节")
	}
	rec, err := a.DB.GetRecord(ctx, "_renewalDeclarations", id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err == nil && text(rec.Data, "status") == "待核对" {
		return map[string]any{"success": true, "alreadyPending": true}, nil
	}
	rec.Collection = "_renewalDeclarations"
	rec.ID = id
	rec.OwnerID = sub.OwnerID
	rec.Data = map[string]any{"subscriptionId": id, "name": sub.Data["name"], "member": sub.Data["member"], "plan": sub.Data["plan"], "status": "待核对", "note": note, "declaredAt": time.Now().UTC().Format(time.RFC3339)}
	_, err = a.DB.SaveRecord(ctx, rec)
	return map[string]any{"success": err == nil, "message": "续期声明已提交，期限未自动改变"}, err
}
func (a *App) membershipConfirmRenewal(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	declaration, err := a.DB.GetRecord(ctx, "_renewalDeclarations", in.TargetID)
	if err != nil {
		return nil, err
	}
	if text(declaration.Data, "status") != "待核对" {
		return map[string]any{"success": true, "alreadyProcessed": true}, nil
	}
	if int64(number(in.Params, "recordVersion")) != declaration.Version {
		return nil, errors.New("续期声明已更新，请刷新后重新核对")
	}
	now := time.Now().UTC()
	declaration.Data["reviewedBy"] = u.ID
	declaration.Data["reviewedAt"] = now.Format(time.RFC3339)
	declaration.Data["reviewNote"] = text(in.Params, "note")
	changes := []store.Record{}
	if in.Action == "subscription.renewal.reject" {
		declaration.Data["status"] = "已拒绝"
	} else {
		if !boolean(in.Params, "confirmed") {
			return nil, errors.New("请先确认已人工核对续期条件")
		}
		days := int(number(in.Params, "days"))
		if days < 1 || days > 3660 {
			return nil, errors.New("续期天数为1–3660")
		}
		sub, err := a.DB.GetRecord(ctx, "subscriptions", text(declaration.Data, "subscriptionId"))
		if err != nil {
			return nil, err
		}
		if sub.OwnerID != declaration.OwnerID {
			return nil, errors.New("套餐归属已改变")
		}
		base := dateTime(text(sub.Data, "expires"))
		if base.IsZero() {
			return nil, errors.New("长期套餐无需延长到期时间")
		}
		if base.Before(now) {
			base = now
		}
		sub.Data["expires"] = base.AddDate(0, 0, days).Format(time.RFC3339)
		declaration.Data["status"] = "已续期"
		declaration.Data["days"] = days
		declaration.Data["expires"] = sub.Data["expires"]
		changes = append(changes, sub)
	}
	history := store.Record{Collection: "_renewalHistory", ID: newID(), OwnerID: declaration.OwnerID, Data: clone(declaration.Data)}
	changes = append(changes, declaration, history)
	_, err = a.DB.CompareAndSaveRecords(ctx, changes)
	if err == nil {
		a.reconcileUsers(ctx, u)
	}
	return map[string]any{"success": err == nil, "message": "已保存核对结果；用量未重置"}, err
}
func (a *App) mergedView(w http.ResponseWriter, r *http.Request) {
	rec, e := a.DB.GetRecord(r.Context(), "_mergedSubscriptions", current(r).ID)
	if errors.Is(e, store.ErrNotFound) {
		respond(w, 200, map[string]any{"enabled": false})
		return
	}
	if e != nil {
		fail(w, 500, "storage_error", "读取合并订阅失败")
		return
	}
	respond(w, 200, rec.Data)
}
func (a *App) mergedSave(w http.ResponseWriter, r *http.Request) {
	memberLinkMu.Lock()
	defer memberLinkMu.Unlock()
	var in struct {
		Enabled bool `json:"enabled"`
		Rotate  bool `json:"rotate"`
	}
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	rec, e := a.DB.GetRecord(r.Context(), "_mergedSubscriptions", u.ID)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	if rec.Data == nil {
		rec = store.Record{Collection: "_mergedSubscriptions", ID: u.ID, OwnerID: u.ID, Data: map[string]any{}}
	}
	if in.Rotate || text(rec.Data, "tokenHash") == "" {
		token := newID() + newID()
		rec.Data["tokenHash"] = membershipHash(token)
		rec.Data["url"] = strings.TrimRight(a.Config.PublicURL, "/") + "/api/merged-subscribe?token=" + url.QueryEscape(token)
	}
	rec.Data["enabled"] = in.Enabled
	if _, e = a.DB.SaveRecord(r.Context(), rec); e != nil {
		fail(w, 409, "conflict", "设置已更新，请重新读取")
		return
	}
	a.audit(r.Context(), u, "subscription.merged.update", u.ID, nil)
	respond(w, 200, rec.Data)
}
func (a *App) mergedDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := r.URL.Query().Get("token")
	if len(token) < 24 || len(token) > 200 {
		fail(w, 404, "not_found", "订阅不可用")
		return
	}
	hash := membershipHash(token)
	records, e := a.DB.ListRecords(r.Context(), "_mergedSubscriptions", "")
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	for _, rec := range records {
		if !boolean(rec.Data, "enabled") || subtle.ConstantTimeCompare([]byte(hash), []byte(text(rec.Data, "tokenHash"))) != 1 {
			continue
		}
		subs, e := a.DB.ListRecords(r.Context(), "subscriptions", rec.OwnerID)
		if e != nil {
			fail(w, 500, "storage_error", "读取失败")
			return
		}
		permitted := []store.Record{}
		denied := 0
		for _, sub := range subs {
			if membershipIPAllowed(sub, requestIP(r)) {
				permitted = append(permitted, sub)
			} else {
				denied++
			}
		}
		subs = permitted
		sort.Slice(subs, func(i, j int) bool { return subs[i].ID < subs[j].ID })
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "clash"
		}
		body, mime, skipped, e := a.renderMergedSubscription(r.Context(), subs, format)
		if e != nil {
			fail(w, 422, "invalid_subscription", e.Error())
			return
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("X-ASWired-Skipped-Subscriptions", fmt.Sprint(skipped+denied))
		a.grantEntry(w, r)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
		return
	}
	fail(w, 404, "not_found", "订阅不可用")
}

func (a *App) membershipResetTraffic(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	key := text(in.Params, "requestId")
	if len(key) < 16 || len(key) > 100 || !boolean(in.Params, "confirmed") {
		return nil, errors.New("请明确确认本次流量重置")
	}
	if previous, err := a.DB.GetRecord(ctx, "_usageResets", key); err == nil {
		if previous.OwnerID != u.ID || text(previous.Data, "subscriptionId") != in.TargetID {
			return nil, errors.New("重置请求标识重复")
		}
		return map[string]any{"success": true, "alreadyProcessed": true}, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	sub, err := a.DB.GetRecord(ctx, "subscriptions", in.TargetID)
	if err != nil {
		return nil, err
	}
	if sub.Version != int64(number(in.Params, "recordVersion")) {
		return nil, errors.New("套餐已更新，请重新读取")
	}
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	end := dateTime(text(sub.Data, "cycleEnd"))
	policy := cyclePolicy(plan.Data, sub.Data)
	if !end.After(now) || nextCycleEnd(policy, now).IsZero() {
		end = nextCycleEnd(policy, now)
	}
	sub.Data["cycleStart"] = now.Format(time.RFC3339Nano)
	sub.Data["cycleEnd"] = cycleStamp(end)
	for _, field := range []string{"used", "usedBytes", "uploadBytes", "downloadBytes"} {
		sub.Data[field] = 0.0
	}
	event := store.Record{Collection: "_usageResets", ID: key, OwnerID: u.ID, Data: map[string]any{"subscriptionId": sub.ID, "memberId": sub.OwnerID, "resetAt": now.Format(time.RFC3339Nano)}}
	_, err = a.DB.CompareAndSaveRecords(ctx, []store.Record{sub, event})
	if err == nil {
		a.reconcileUsers(ctx, u)
	}
	return map[string]any{"success": err == nil, "message": "本周期用量已重置，历史流量记录仍保留"}, err
}

func membershipIPAllowed(sub store.Record, remoteAddr string) bool {
	list := stringList(sub.Data["whitelist"])
	if len(list) == 0 || list[0] == "未设置" {
		return true
	}
	host := remoteAddr
	if address, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, entry := range list {
		if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(ip) {
			return true
		}
		if exact := net.ParseIP(entry); exact != nil && exact.Equal(ip) {
			return true
		}
	}
	return false
}
