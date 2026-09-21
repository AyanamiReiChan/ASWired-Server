package httpapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func sortGenerated(records []store.Record) {
	sort.SliceStable(records, func(i, j int) bool {
		x, y := number(records[i].Data, "sortOrder"), number(records[j].Data, "sortOrder")
		if x != y {
			return x < y
		}
		if !records[i].CreatedAt.Equal(records[j].CreatedAt) {
			return records[i].CreatedAt.After(records[j].CreatedAt)
		}
		return records[i].ID < records[j].ID
	})
}

func (a *App) generatedList(w http.ResponseWriter, r *http.Request) {
	records, err := a.DB.ListRecords(r.Context(), generatedSubscriptionCollection, "")
	if err != nil {
		fail(w, 500, "storage_error", "读取订阅列表失败")
		return
	}
	sortGenerated(records)
	rows := []any{}
	for _, rec := range records {
		if boolean(rec.Data, "revoked") {
			continue
		}
		row := generatedLinkRow(rec)
		row["recordVersion"], row["ownerId"], row["updatedAt"] = rec.Version, rec.OwnerID, rec.UpdatedAt
		row["description"], row["templateId"], row["mode"] = text(rec.Data, "description"), text(rec.Data, "templateId"), text(rec.Data, "mode")
		row["hasLink"] = text(rec.Data, "linkToken") != ""
		row["creator"], row["status"] = "已删除用户", "创建者已失效"
		actor, e := a.DB.UserByID(r.Context(), rec.OwnerID)
		if e == nil {
			row["creator"] = actor.Username
			if !actor.Disabled && actor.Role == "admin" && actor.TokenVersion == int64(number(rec.Data, "tokenVersion")) {
				row["status"] = "有效"
				if !time.Now().Before(dateTime(text(rec.Data, "expiresAt"))) {
					row["status"] = "已到期"
				}
			}
		}
		row["metered"] = false
		if subID := text(rec.Data, "subscriptionId"); subID != "" {
			row["statusHint"] = "以套餐当前权限、额度与有效期为准"
			sub, e := a.DB.GetRecord(r.Context(), "subscriptions", subID)
			if e == nil {
				used, _, _, usageErr := a.subscriptionUsage(r.Context(), sub)
				if usageErr == nil {
					row["metered"], row["used"], row["limit"] = true, used/gib, number(sub.Data, "limit")
				}
				if !constant(text(rec.Data, "parentTokenHash"), hashOpaque(text(sub.Data, "token"))) {
					row["status"] = "套餐凭据已轮换"
				}
			} else {
				row["status"] = "套餐已删除"
			}
		}
		rows = append(rows, row)
	}
	w.Header().Set("Cache-Control", "private, no-store")
	respond(w, 200, map[string]any{"rows": rows})
}

func (a *App) generatedDetail(w http.ResponseWriter, r *http.Request) {
	rec, err := a.DB.GetRecord(r.Context(), generatedSubscriptionCollection, r.PathValue("id"))
	if err != nil || boolean(rec.Data, "revoked") {
		fail(w, 404, "not_found", "订阅不存在")
		return
	}
	// Explicit detail reads may reveal the link; list responses never do.
	row := generatedLinkRow(rec)
	for _, key := range []string{"description", "nodeIds", "subscriptionId", "mode", "templateId", "categories"} {
		row[key] = rec.Data[key]
	}
	row["recordVersion"], row["ownerId"] = rec.Version, rec.OwnerID
	if token := text(rec.Data, "linkToken"); token != "" {
		row["url"] = "/api/generated-subscribe?token=" + url.QueryEscape(token)
	}
	w.Header().Set("Cache-Control", "private, no-store")
	respond(w, 200, map[string]any{"row": row})
}

func (a *App) generatedUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RecordVersion int64     `json:"recordVersion"`
		Name          *string   `json:"name"`
		Description   *string   `json:"description"`
		TemplateID    *string   `json:"templateId"`
		NodeIDs       *[]string `json:"nodeIds"`
		Categories    *[]string `json:"categories"`
		ExpiresAt     *string   `json:"expiresAt"`
	}
	if !decode(w, r, &in) {
		return
	}
	templateMu.Lock()
	defer templateMu.Unlock()
	rec, err := a.DB.GetRecord(r.Context(), generatedSubscriptionCollection, r.PathValue("id"))
	if err != nil || boolean(rec.Data, "revoked") {
		fail(w, 404, "not_found", "订阅不存在")
		return
	}
	if rec.Version != in.RecordVersion {
		fail(w, 409, "conflict", "订阅已改变，请刷新后重试")
		return
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 200 {
			fail(w, 400, "invalid_name", "名称不能为空且不能超过 200 字节")
			return
		}
		rec.Data["name"] = name
	}
	if in.Description != nil {
		if len(*in.Description) > 2000 {
			fail(w, 400, "invalid_description", "说明不能超过 2000 字节")
			return
		}
		rec.Data["description"] = *in.Description
	}
	if in.TemplateID != nil {
		rec.Data["templateId"] = *in.TemplateID
		rec.Data["mode"] = "custom"
		if *in.TemplateID != "" {
			rec.Data["mode"] = "template"
		}
	}
	if in.NodeIDs != nil {
		rec.Data["nodeIds"] = *in.NodeIDs
	}
	if in.Categories != nil {
		rec.Data["categories"] = *in.Categories
	}
	actor, err := a.DB.UserByID(r.Context(), rec.OwnerID)
	if err != nil || actor.Disabled || actor.Role != "admin" || actor.TokenVersion != int64(number(rec.Data, "tokenVersion")) {
		fail(w, 422, "inactive", "创建者权限已改变，请重新生成订阅")
		return
	}
	var config generatorInput
	raw, _ := json.Marshal(rec.Data)
	if json.Unmarshal(raw, &config) != nil {
		fail(w, 422, "invalid_config", "订阅配置无效")
		return
	}
	// Preserve the original creator's scope, parent credential binding and IP policy.
	_, _, _, sub, err := a.renderGenerated(r.Context(), actor, config, requestIP(r), text(rec.Data, "parentTokenHash"))
	if err != nil {
		fail(w, 422, "invalid_config", err.Error())
		return
	}
	if in.ExpiresAt != nil {
		expiry := dateTime(*in.ExpiresAt)
		if !expiry.After(time.Now()) || expiry.After(time.Now().Add(90*24*time.Hour)) {
			fail(w, 400, "invalid_expiry", "到期时间须在未来 90 天内")
			return
		}
		if parent := dateTime(text(sub.Data, "expires")); !parent.IsZero() && expiry.After(parent) {
			fail(w, 400, "invalid_expiry", "不能晚于套餐到期时间")
			return
		}
		rec.Data["expiresAt"] = expiry.UTC().Format(time.RFC3339Nano)
	}
	if _, err = a.DB.SaveRecord(r.Context(), rec); err != nil {
		fail(w, 409, "conflict", "订阅已改变，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "subscription.generate.update", rec.ID, nil)
	respond(w, 200, map[string]any{"success": true})
}

func (a *App) generatedDelete(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RecordVersion int64 `json:"recordVersion"`
	}
	if !decode(w, r, &in) {
		return
	}
	rec, err := a.DB.GetRecord(r.Context(), generatedSubscriptionCollection, r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "订阅不存在")
		return
	}
	if rec.Version != in.RecordVersion {
		fail(w, 409, "conflict", "订阅已改变，请刷新后重试")
		return
	}
	rec.Data["revoked"] = true
	delete(rec.Data, "linkToken")
	if _, err = a.DB.SaveRecord(r.Context(), rec); err != nil {
		fail(w, 409, "conflict", "订阅已改变，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "subscription.generate.revoke", rec.ID, nil)
	respond(w, 200, map[string]any{"success": true})
}

func (a *App) generatedOrder(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rows []struct {
			ID      string `json:"id"`
			Version int64  `json:"recordVersion"`
		} `json:"rows"`
	}
	if !decode(w, r, &in) {
		return
	}
	records, err := a.DB.ListRecords(r.Context(), generatedSubscriptionCollection, "")
	if err != nil {
		fail(w, 500, "storage_error", "读取订阅失败")
		return
	}
	byID := map[string]store.Record{}
	for _, rec := range records {
		if !boolean(rec.Data, "revoked") {
			byID[rec.ID] = rec
		}
	}
	if len(in.Rows) != len(byID) {
		fail(w, 409, "conflict", "列表已改变，请刷新后重试")
		return
	}
	ordered := []store.Record{}
	for index, item := range in.Rows {
		rec, ok := byID[item.ID]
		if !ok || rec.Version != item.Version {
			fail(w, 409, "conflict", "列表已改变，请刷新后重试")
			return
		}
		delete(byID, item.ID)
		rec.Data["sortOrder"] = index
		ordered = append(ordered, rec)
	}
	if len(ordered) > 0 {
		if _, err = a.DB.CompareAndSaveRecords(r.Context(), ordered); err != nil {
			fail(w, 409, "conflict", "列表已改变，请刷新后重试")
			return
		}
	}
	respond(w, 200, map[string]any{"success": true})
}
