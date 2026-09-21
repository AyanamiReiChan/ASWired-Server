package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

const temporaryCollection = "_temporarySubscriptions"

func (a *App) registerTemporarySubscriptions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/temporary-subscriptions", a.withUser(a.temporaryList))
	mux.HandleFunc("POST /api/temporary-subscriptions", a.withUser(a.temporaryCreate))
	mux.HandleFunc("DELETE /api/temporary-subscriptions/{id}", a.withUser(a.temporaryRevoke))
	mux.HandleFunc("GET /api/temporary-subscribe", a.temporaryDownload)
}

func temporaryRow(rec store.Record) map[string]any {
	row := map[string]any{"id": rec.ID, "name": rec.Data["name"], "subscriptionId": rec.Data["subscriptionId"], "nodeId": rec.Data["nodeId"], "nodeName": rec.Data["nodeName"], "createdAt": rec.CreatedAt, "expiresAt": rec.Data["expiresAt"], "maxUses": rec.Data["maxUses"], "used": rec.Data["used"], "revoked": rec.Data["revoked"]}
	row["remaining"] = max(0, number(rec.Data, "maxUses")-number(rec.Data, "used"))
	status := "有效"
	if boolean(rec.Data, "revoked") {
		status = "已撤销"
	} else if !time.Now().Before(dateTime(text(rec.Data, "expiresAt"))) {
		status = "已到期"
	} else if number(rec.Data, "used") >= number(rec.Data, "maxUses") {
		status = "次数已用尽"
	}
	row["status"] = status
	return row
}

func (a *App) temporaryList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u := current(r)
	records, e := a.DB.ListRecords(r.Context(), temporaryCollection, u.ID)
	if e != nil {
		fail(w, 503, "storage_error", "临时订阅暂不可用")
		return
	}
	rows := []any{}
	for i := len(records) - 1; i >= 0; i-- {
		rows = append(rows, temporaryRow(records[i]))
	}
	subscriptions, e := a.DB.ListRecords(r.Context(), "subscriptions", u.ID)
	if e != nil {
		fail(w, 503, "storage_error", "套餐暂不可用")
		return
	}
	options := []any{}
	for _, sub := range subscriptions {
		nodes, e := a.eligibleNodes(r.Context(), sub)
		if e != nil {
			continue
		}
		visible := []any{}
		for _, node := range nodes {
			visible = append(visible, map[string]any{"id": node.ID, "name": node.Data["name"], "protocol": node.Data["protocol"]})
		}
		options = append(options, map[string]any{"id": sub.ID, "name": sub.Data["name"], "plan": sub.Data["plan"], "expires": sub.Data["expires"], "nodes": visible})
	}
	respond(w, 200, map[string]any{"rows": rows, "subscriptions": options})
}

func (a *App) temporaryCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Name             string `json:"name"`
		SubscriptionID   string `json:"subscriptionId"`
		NodeID           string `json:"nodeId"`
		ExpiresInSeconds int64  `json:"expiresInSeconds"`
		MaxUses          int    `json:"maxUses"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiresInSeconds < 60 || in.ExpiresInSeconds > 7*86400 || in.MaxUses < 1 || in.MaxUses > 1000 || len(in.Name) > 200 {
		fail(w, 400, "invalid_limit", "有效期须为60秒至7天，访问次数须为1至1000")
		return
	}
	u := current(r)
	sub, e := a.DB.GetRecord(r.Context(), "subscriptions", in.SubscriptionID)
	if e != nil || sub.OwnerID != u.ID {
		fail(w, 403, "scope_denied", "只能从自己的套餐创建临时订阅")
		return
	}
	nodes, e := a.eligibleNodes(r.Context(), sub)
	if e != nil {
		fail(w, 403, "subscription_inactive", e.Error())
		return
	}
	var selected store.Record
	for _, node := range nodes {
		if node.ID == in.NodeID {
			selected = node
			break
		}
	}
	if selected.ID == "" {
		fail(w, 403, "node_denied", "该节点不在此套餐当前允许的范围内")
		return
	}

	expires := time.Now().UTC().Add(time.Duration(in.ExpiresInSeconds) * time.Second)
	if parent := dateTime(text(sub.Data, "expires")); !parent.IsZero() && parent.Before(expires) {
		expires = parent
	}
	token := newID() + newID()
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = text(selected.Data, "name") + " · 临时订阅"
	}
	rec, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: temporaryCollection, ID: hashOpaque(token), OwnerID: u.ID, Data: map[string]any{"name": name, "subscriptionId": sub.ID, "nodeId": selected.ID, "nodeName": selected.Data["name"], "parentTokenHash": hashOpaque(text(sub.Data, "token")), "expiresAt": expires.Format(time.RFC3339Nano), "maxUses": in.MaxUses, "used": 0, "revoked": false}})
	if e != nil {
		fail(w, 503, "storage_error", "无法创建临时订阅")
		return
	}
	a.audit(r.Context(), u, "subscription.temporary.create", rec.ID, map[string]any{"subscriptionId": sub.ID, "nodeId": selected.ID, "maxUses": in.MaxUses, "expiresAt": expires})
	respond(w, 201, map[string]any{"row": temporaryRow(rec), "token": token, "url": strings.TrimRight(a.Config.PublicURL, "/") + "/api/temporary-subscribe?token=" + url.QueryEscape(token)})
}

func (a *App) temporaryRevoke(w http.ResponseWriter, r *http.Request) {
	rec, e := a.DB.GetRecord(r.Context(), temporaryCollection, r.PathValue("id"))
	u := current(r)
	if e != nil || rec.OwnerID != u.ID {
		fail(w, 404, "not_found", "临时订阅不存在")
		return
	}
	if !boolean(rec.Data, "revoked") {
		rec.Data["revoked"] = true
		if _, e = a.DB.SaveRecord(r.Context(), rec); e != nil {
			fail(w, 409, "conflict", "临时订阅已改变，请刷新后重试")
			return
		}
	}
	a.audit(r.Context(), u, "subscription.temporary.revoke", rec.ID, nil)
	respond(w, 200, map[string]any{"success": true})
}

func (a *App) temporarySource(ctx context.Context, rec store.Record, ip string) (store.Record, store.Record, error) {
	if boolean(rec.Data, "revoked") || !time.Now().Before(dateTime(text(rec.Data, "expiresAt"))) || number(rec.Data, "used") >= number(rec.Data, "maxUses") {
		return store.Record{}, store.Record{}, errors.New("临时订阅已过期、撤销或次数用尽")
	}
	sub, e := a.DB.GetRecord(ctx, "subscriptions", text(rec.Data, "subscriptionId"))
	if e != nil || sub.OwnerID != rec.OwnerID || !constant(hashOpaque(text(sub.Data, "token")), text(rec.Data, "parentTokenHash")) {
		return sub, store.Record{}, errors.New("原套餐权限已改变")
	}
	if !membershipIPAllowed(sub, ip) {
		return sub, store.Record{}, errors.New("访问地址不在原套餐白名单内")
	}
	nodes, e := a.eligibleNodes(ctx, sub)
	if e != nil {
		return sub, store.Record{}, e
	}
	for _, node := range nodes {
		if node.ID == text(rec.Data, "nodeId") {
			return sub, node, nil
		}
	}
	return sub, store.Record{}, errors.New("节点已不在原套餐允许范围内")
}

func (a *App) temporaryDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "临时订阅仅支持GET下载")
		return
	}
	token := r.URL.Query().Get("token")
	if len(token) < 24 || len(token) > 200 {
		fail(w, 404, "not_found", "临时订阅不可用")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), temporaryCollection, hashOpaque(token))
	if e != nil {
		fail(w, 404, "not_found", "临时订阅不可用")
		return
	}
	sub, node, e := a.temporarySource(r.Context(), rec, requestIP(r))
	if e != nil {
		fail(w, 403, "temporary_inactive", e.Error())
		return
	}
	renderSub := sub
	renderSub.Data = clone(sub.Data)
	delete(renderSub.Data, "templateId")
	delete(renderSub.Data, "scriptId")
	renderSub.Data["skipTemplates"] = true
	output, mime, skipped, e := a.renderSubscription(r.Context(), renderSub, []store.Record{node}, normalizeFormat(r.URL.Query().Get("format")))
	if e != nil {
		fail(w, 422, "incompatible_config", e.Error())
		return
	}

	for attempt := 0; attempt < 12; attempt++ {
		currentSub, currentNode, err := a.temporarySource(r.Context(), rec, requestIP(r))
		if err != nil {
			fail(w, 403, "temporary_inactive", err.Error())
			return
		}
		if currentSub.Version != sub.Version || currentNode.Version != node.Version {
			fail(w, 409, "source_changed", "套餐或节点配置已更新，请重试")
			return
		}
		rec.Data["used"] = number(rec.Data, "used") + 1
		rec.Data["lastUsedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
		updated, err := a.DB.SaveRecord(r.Context(), rec)
		if err == nil {
			_, up, down, _ := a.subscriptionUsage(r.Context(), sub)
			header := fmt.Sprintf("upload=%.0f; download=%.0f; total=%.0f; expire=%d", up, down, number(sub.Data, "limit")*gib, dateTime(text(updated.Data, "expiresAt")).Unix())
			w.Header().Set("Subscription-Userinfo", header)
			w.Header().Set("X-ASWired-Temporary-Remaining", strconv.Itoa(int(number(updated.Data, "maxUses")-number(updated.Data, "used"))))
			w.Header().Set("X-ASWired-Skipped-Nodes", strconv.Itoa(skipped))
			w.Header().Set("Content-Type", mime)
			w.WriteHeader(200)
			_, _ = w.Write([]byte(output))
			return
		}
		if !errors.Is(err, store.ErrConflict) {
			fail(w, 503, "storage_error", "无法记录临时订阅访问")
			return
		}
		rec, err = a.DB.GetRecord(r.Context(), temporaryCollection, rec.ID)
		if err != nil {
			fail(w, 403, "temporary_inactive", "临时订阅不可用")
			return
		}
	}
	fail(w, 409, "busy", "临时订阅正在被使用，请重试")
}
