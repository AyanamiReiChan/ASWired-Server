package httpapi

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var collections = []string{"servers", "members", "plans", "subscriptions", "inbounds", "outbounds", "nodes", "sources", "policies", "certificates", "notifications", "sites", "forwards", "relays", "shares", "speedtests", "endpoints", "rules", "tokens", "redeemCodes", "announcements", "dnsProviders", "extensions"}
var secrets = map[string]bool{"password": true, "passwordHash": true, "privateKey": true, "private_key": true, "serverToken": true, "agentToken": true, "token": true, "secret": true, "credential": true, "apiKey": true, "apiToken": true, "uri": true, "realitySettings": true, "config": true, "secretAccessKey": true, "clientSecret": true, "refreshToken": true, "sessionToken": true, "encryptionPassword": true, "credentialPassword": true, "credentialUUID": true, "xuiPassword": true}

func init() {
	for _, key := range []string{"zoneToken", "securityToken", "eabHmacKey"} {
		secrets[key] = true
	}
	collections = append(collections, "schedules")
	for _, key := range []string{"private-key", "pre-shared-key", "preSharedKey", "psk", "auth", "auth-str", "auth_str", "obfs", "obfs-password", "obfsPassword"} {
		secrets[key] = true
	}
	for _, key := range []string{"Authorization", "authorization", "accessKeySecret", "secretKey", "SecretKey", "AccessKeySecret", "refresh_token", "access_token", "api_token", "tokenHash", "subscriptionURL", "shortCode", "shortUrl", "shareUrl", "enrollmentToken", "telegramWebhookSecret", "xuiToken", "turnstileSecret", "entryKey"} {
		secrets[key] = true
	}
}
func operationsCollection(collection string) bool {
	switch collection {
	case "tasks", "audit", "certificates", "notifications", "extensions", "schedules":
		return true
	default:
		return false
	}
}

func adminOnlyCollection(collection string) bool {
	return collection == "relays" || collection == "sources" || operationsCollection(collection)
}

func allowedCollection(s string) bool {
	for _, c := range collections {
		if c == s {
			return true
		}
	}
	return false
}
func sanitize(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if secrets[k] {
			continue
		}
		switch sub := v.(type) {
		case map[string]any:
			out[k] = sanitize(sub)
		case []any:
			arr := make([]any, len(sub))
			for i, item := range sub {
				if mm, ok := item.(map[string]any); ok {
					arr[i] = sanitize(mm)
				} else {
					arr[i] = item
				}
			}
			out[k] = arr
		default:
			out[k] = v
		}
	}
	return out
}
func rowOf(rec store.Record, detail bool) map[string]any {
	row := clone(rec.Data)
	if rec.Collection == "servers" {
		for key := range row {
			if strings.HasPrefix(strings.ToLower(key), "xui") {
				delete(row, key)
			}
		}
		if !nativeServer(rec) {
			row["connection"] = "unsupported"
			row["managementMode"] = "unsupported"
			row["status"] = "需重新接入"
			row["connectionError"] = errUnsupportedServerConnection.Error()
		}
	}
	row["id"] = rec.ID
	row["recordVersion"] = rec.Version
	row["createdAt"] = rec.CreatedAt
	row["updatedAt"] = rec.UpdatedAt
	if !detail {
		return sanitize(row)
	}
	return row
}
func capabilityMap() map[string]any {
	return map[string]any{
		"logRetentionDays": logRetentionDays, "licenseRequired": false, "darkOnly": true, "userAuthentication": "JWT", "agentProtocol": "aswired-agent-v1", "upstreamWireCompatible": false,
		"database": []string{"sqlite", "postgres"}, "externalProbe": "Komari 1.2.5-fix2",
		"implemented":               []string{"accounts", "jwt", "totp", "passkey", "qr-login", "callback-login", "api-tokens", "mcp", "inventory", "packages", "redemption", "manual-renewal", "subscriptions", "merged-subscriptions", "temporary-subscriptions", "configuration", "templates", "agent-channel", "komari-probe", "probe-history", "audit", "settings", "behavior-limits", "traffic-ledger", "forwarding", "forward-chains", "wireguard", "warp-user-config", "acme", "ddns", "backup-restore", "encrypted-remote-backup", "federation", "opaque-agent-federation", "telegram", "turnstile", "silent-entry", "source-home-fetch", "ip-database"},
		"agentCapabilitiesRequired": []string{"core.config.apply", "core.users.sync", "core.stats", "certificate.deploy", "site.apply"},
		"platformValidationPending": []string{"linux-host-networking", "linux-splice-runtime", "postgresql-instance", "docker-service-installation"},
		"compatibilityPolicy":       "Original ASWired behavior; no private upstream protocol, login trust or backup compatibility claim. Runtime capabilities must be checked on each Agent.",
	}
}

func (a *App) capabilities(w http.ResponseWriter, r *http.Request) { respond(w, 200, capabilityMap()) }
func (a *App) state(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	data := map[string]any{}
	for _, c := range collections {
		if u.Role != "admin" && adminOnlyCollection(c) {
			continue
		}
		rows, e := a.visibleRows(r, c)
		if e != nil {
			fail(w, 500, "storage_error", "读取工作区失败")
			return
		}
		data[c] = rows
	}
	data["carpools"] = []any{}
	data["billing"] = []any{}
	if u.Role == "admin" {
		tasks, e := a.DB.ListTasks(r.Context(), "", 200)
		if e != nil {
			fail(w, 500, "storage_error", "读取任务失败")
			return
		}
		taskRows := []any{}
		for _, task := range tasks {
			taskRows = append(taskRows, taskRow(task))
		}
		data["tasks"] = taskRows
		events, e := a.DB.ListAudit(r.Context(), 200)
		if e != nil {
			fail(w, 500, "storage_error", "读取日志失败")
			return
		}
		auditRows := []any{}
		for _, v := range events {
			auditRows = append(auditRows, map[string]any{"id": v.ID, "name": v.Action, "actor": v.ActorID, "resource": v.Target, "action": v.Action, "result": "已记录", "created": v.CreatedAt.Format(time.RFC3339), "detail": v.Details})
		}
		data["audit"] = auditRows
	}
	settings := a.settingsMap(r)
	data["settings"] = []any{map[string]any{"id": "settings", "name": "系统设置", "values": settings}}
	respond(w, 200, map[string]any{"user": u, "data": data, "settings": settings, "capabilities": capabilityMap()})
}
func (a *App) visibleRows(r *http.Request, collection string) ([]map[string]any, error) {
	u := current(r)
	rows := []map[string]any{}
	if u.Role != "admin" && collection != "subscriptions" && collection != "plans" && collection != "nodes" && collection != "members" && collection != "announcements" && collection != "tokens" {
		return rows, nil
	}
	owner := ""
	if u.Role != "admin" && (collection == "subscriptions" || collection == "members" || collection == "tokens") {
		owner = u.ID
	}
	recs, e := a.DB.ListRecords(r.Context(), collection, owner)
	if e != nil {
		return nil, e
	}
	var assigned map[string]bool
	if u.Role != "admin" && (collection == "plans" || collection == "nodes") {
		assigned = map[string]bool{}
		subs, e := a.DB.ListRecords(r.Context(), "subscriptions", u.ID)
		if e != nil {
			return nil, e
		}
		for _, sub := range subs {
			if collection == "plans" {
				assigned[text(sub.Data, "planId")] = true
			} else {
				nodes, _ := a.eligibleNodes(r.Context(), sub)
				for _, n := range nodes {
					assigned[n.ID] = true
				}
			}
		}
	}
	for _, rec := range recs {
		if u.Role != "admin" && collection == "nodes" && rec.OwnerID != "" && rec.OwnerID != u.ID {
			continue
		}
		if assigned != nil && !assigned[rec.ID] {
			continue
		}
		row := rowOf(rec, false)
		if collection == "certificates" {
			if operation, err := a.DB.GetRecord(r.Context(), "_operationSchedule", "certificate:"+rec.ID); err == nil {
				row["lastOperation"] = map[string]any{"status": operation.Data["status"], "error": operation.Data["error"], "lastAttempt": operation.Data["lastAttempt"]}
			}
		}
		if collection == "nodes" {
			if u.Role != "admin" {
				row = memberNodeRow(rec)
			} else {
				row["canManage"] = true
			}
			if strings.TrimSpace(text(row, "region")) == "" {
				server, _ := a.DB.GetRecord(r.Context(), "servers", text(rec.Data, "serverId"))
				if region := strings.TrimSpace(text(server.Data, "region")); region != "" {
					row["region"] = region
				} else {
					host := text(rec.Data, "host")
					if host == "" {
						host = text(server.Data, "publicAddress")
					}
					if host == "" {
						host = text(server.Data, "address")
					}
					if country := a.lookupHostCountry(r.Context(), host); country != "" {
						row["region"] = country
					}
				}
			}
		}
		if collection == "speedtests" {
			if task, err := a.DB.GetTask(r.Context(), rec.ID); err == nil {
				row["status"], row["error"] = task.Status, task.Error
			}
		}
		if collection == "endpoints" {
			a.mu.Lock()
			p := a.peers[rec.ID]
			row["online"] = p != nil && time.Since(p.LastSeen) < 45*time.Second
			row["boundedSpeedtest"] = p != nil && p.Capabilities["speedtest_bounded"]
			a.mu.Unlock()
			if obs, err := a.DB.GetRecord(r.Context(), "_homeObservations", rec.ID); err == nil {
				row["sourceMode"], row["platform"] = obs.Data["sourceMode"], obs.Data["platform"]
			}
		}
		if collection == "servers" {
			a.mu.Lock()
			p := a.peers[rec.ID]
			if p != nil && time.Since(p.LastSeen) < 45*time.Second {
				row["status"] = "在线"
				row["activeConnection"] = serverConnectionLabel(strings.ToLower(p.Transport))
				row["appliedConnection"] = p.ConnectionMode
				row["connectionSwitchSupported"] = p.Capabilities["connection_modes"]
				row["lastSeen"] = p.LastSeen
				row["agentVersion"] = p.Version
				row["xray_mode"] = p.Mode
				row["capabilities"] = p.Capabilities
			} else if p != nil {
				row["status"] = "离线"
			} else {
				row["status"] = "待接入"
			}
			a.mu.Unlock()
		}
		if collection == "servers" {
			// Xray belongs to the managed Agent even when host metrics use Komari.
			row["probeSource"] = "komari"
			delete(row, "core")
			for _, key := range []string{"agentState", "observation", "cpu", "memory", "upload", "download"} {
				delete(row, key)
			}
			if native, err := a.DB.GetRecord(r.Context(), "_observations", rec.ID); err == nil {
				row["agentUpdate"] = native.Data["agent_update"]
				if core, ok := native.Data["core"].(map[string]any); ok {
					row["agentState"] = map[string]any{"core": sanitize(core)}
					if version := strings.TrimSpace(text(core, "core_version")); version != "" {
						row["core"] = version
					}
				}
			}
			obs, probeOnline, _ := a.selectedObservation(r.Context(), rec)
			if billing, err := a.merchantCurrent(r.Context(), rec.ID); err == nil {
				row["merchantTraffic"] = billing
				row["limit"] = billing["limitGB"]
			}
			row["probeOnline"] = probeOnline
			row["probeStatus"] = "离线"
			if text(rec.Data, "komariUUID") == "" {
				row["probeStatus"] = "未绑定 Komari"
			} else if obs == nil {
				row["probeStatus"] = "等待 Komari 同步"
			} else if probeOnline {
				row["probeStatus"] = "在线"
			}
			if obs != nil {
				if strings.TrimSpace(text(row, "region")) == "" {
					row["region"] = text(obs, "region")
				}
				row["cpu"] = obs["cpu_percent"]
				row["memory"] = obs["memory_percent"]
				if row["memory"] == nil && number(obs, "memory_total") > 0 {
					row["memory"] = number(obs, "memory_used") / number(obs, "memory_total") * 100
				}
				row["upload"] = obs["network_tx_per_second"]
				row["download"] = obs["network_rx_per_second"]
				row["observation"] = sanitize(obs)
			}
			if !nativeServer(rec) {
				row["connection"] = "unsupported"
				row["status"] = "需重新接入"
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (a *App) list(w http.ResponseWriter, r *http.Request) {
	c := r.PathValue("collection")
	if current(r).Role != "admin" && adminOnlyCollection(c) {
		fail(w, 403, "forbidden", "该资源仅管理员可查看")
		return
	}
	if !allowedCollection(c) {
		fail(w, 404, "unknown_collection", "该资源不存在")
		return
	}
	rows, e := a.visibleRows(r, c)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	respond(w, 200, map[string]any{"rows": rows})
}
func (a *App) get(w http.ResponseWriter, r *http.Request) {
	c, id := r.PathValue("collection"), r.PathValue("id")
	if current(r).Role != "admin" && (c == "nodes" || adminOnlyCollection(c)) {
		fail(w, 403, "forbidden", "该资源仅管理员可查看")
		return
	}
	if c == "tasks" {
		task, e := a.DB.GetTask(r.Context(), id)
		if e != nil || task.LogsDeleted {
			fail(w, 404, "not_found", "任务不存在")
			return
		}
		row := taskRow(task)
		var raw any
		_ = json.Unmarshal(task.Result, &raw)
		row["result"] = raw
		respond(w, 200, map[string]any{"row": row})
		return
	}
	if !allowedCollection(c) {
		fail(w, 404, "unknown_collection", "该资源不存在")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), c, id)
	if e != nil {
		fail(w, 404, "not_found", "记录不存在")
		return
	}
	u := current(r)
	if u.Role != "admin" && (rec.OwnerID != u.ID || (c != "subscriptions" && c != "members" && !memberResource(c))) {
		fail(w, 403, "forbidden", "没有该记录的访问权限")
		return
	}
	row := rowOf(rec, true)
	if c == "members" {
		delete(row, "password")
	}
	if c == "servers" {
		row = sanitize(row)
	}
	if c == "dnsProviders" || c == "certificates" {
		row = settingsProjection(row)
	}
	if memberResource(c) {
		row["canManage"] = u.Role == "admin" || rec.OwnerID == u.ID
	}
	respond(w, 200, map[string]any{"row": row})
}
func (a *App) save(w http.ResponseWriter, r *http.Request) {
	c := r.PathValue("collection")
	if c == "policies" || c == "plans" {
		templateMu.Lock()
		defer templateMu.Unlock()
	}
	if c == "certificates" || c == "dnsProviders" {
		certificateMu.Lock()
		defer certificateMu.Unlock()
	}
	if !allowedCollection(c) {
		fail(w, 404, "unknown_collection", "该资源不存在")
		return
	}
	u := current(r)
	if u.Role != "admin" && (c == "nodes" || !memberResource(c)) {
		fail(w, 403, "forbidden", "需要管理员权限")
		return
	}
	var in struct {
		Row map[string]any `json:"row"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Row == nil {
		fail(w, 400, "invalid_row", "缺少记录内容")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		id = text(in.Row, "id")
	}
	if id == "" {
		id = newID()
	}
	if strings.ContainsAny(id, "/\\\x00") || len(id) > 200 {
		fail(w, 400, "invalid_id", "记录标识无效")
		return
	}
	previous, e := a.DB.GetRecord(r.Context(), c, id)
	exists := e == nil
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	if c == "relays" && r.Method == "POST" && exists {
		fail(w, 409, "conflict", "该节点已配置中转，请删除旧映射后重新添加")
		return
	}
	if r.Method == "PUT" && !exists {
		fail(w, 404, "not_found", "记录不存在")
		return
	}
	if exists && number(in.Row, "recordVersion") > 0 && int64(number(in.Row, "recordVersion")) != previous.Version {
		fail(w, 409, "conflict", "记录已更新，请重新打开后再保存")
		return
	}
	if c == "servers" && exists && !nativeServer(previous) && !nativeServerConnection(text(in.Row, "connection")) {
		fail(w, 400, "unsupported_connection", errUnsupportedServerConnection.Error())
		return
	}
	row := clone(in.Row)
	delete(row, "id")
	delete(row, "recordVersion")
	delete(row, "createdAt")
	delete(row, "updatedAt")
	delete(row, "canManage")
	if exists {
		for k, v := range previous.Data {
			if _, ok := row[k]; !ok {
				row[k] = v
			}
		}
	}
	if exists && u.Role == "admin" {
		preserveSettingsSecrets(row, previous.Data)
	}
	delete(row, "canManage")
	delete(row, "canTest")
	if c == "policies" {
		row["isDefault"] = boolean(previous.Data, "isDefault")
		row["userVisible"] = boolean(previous.Data, "userVisible")
	}
	delete(row, "subscriptionAuthorized")
	if u.Role != "admin" {
		var err error
		row, err = a.prepareMemberResource(r, c, row, previous, exists)
		if err != nil {
			fail(w, 403, "member_resource_denied", err.Error())
			return
		}
	}
	if strings.TrimSpace(text(row, "name")) == "" {
		fail(w, 400, "name_required", "请填写名称")
		return
	}
	if e = a.validateRecord(r, c, id, row, exists); e != nil {
		fail(w, 400, "invalid_record", e.Error())
		return
	}
	if c == "plans" || c == "members" {
		if e = validateLimitConfiguration(row); e != nil {
			fail(w, 400, "invalid_limits", e.Error())
			return
		}
	}
	var memberUser *store.User
	owner := previous.OwnerID
	if u.Role != "admin" {
		owner = u.ID
	}
	if c == "members" {
		prepared, err := a.prepareMember(r, id, row, exists)
		if err != nil {
			fail(w, 400, "invalid_member", err.Error())
			return
		}
		memberUser = &prepared
		owner = prepared.ID
	}
	if c == "subscriptions" {
		var err error
		owner, err = a.prepareSubscription(r, id, row, exists)
		if err != nil {
			fail(w, 400, "invalid_subscription", err.Error())
			return
		}
	}
	if c == "policies" && text(row, "content") != "" {
		if exists && templateType(text(previous.Data, "type")) != templateType(text(row, "type")) {
			fail(w, 400, "invalid_template", "已保存模板不可更改类型，请创建新模板")
			return
		}
		var content string
		content, _, e = normalizeTemplateDocument(text(row, "content"), templateType(text(row, "type")), int(number(row, "version")))
		if e != nil {
			fail(w, 400, "invalid_template", e.Error())
			return
		}
		row["content"] = content
		row["version"] = 3
		delete(row, "sourceContent")
	}
	if c == "inbounds" && exists && (text(previous.Data, "serverId") != text(row, "serverId") || text(previous.Data, "tag") != text(row, "tag")) {
		if err := a.rememberManagedInboundTags(r.Context(), previous); err != nil {
			fail(w, 500, "storage_error", "旧入站任务归属保存失败，请重试")
			return
		}
	}
	record := store.Record{Collection: c, ID: id, OwnerID: owner, Data: row, Version: previous.Version}
	var rec store.Record
	if memberUser != nil {
		rec, e = a.DB.SaveMemberRecord(r.Context(), *memberUser, record, exists)
	} else if u.Role != "admin" && memberResource(c) {
		var saved []store.Record
		saved, e = a.DB.CompareAndSaveOwnedResources(r.Context(), u.ID, a.memberQuotas(r.Context(), u.ID), []store.Record{record})
		if e == nil {
			rec = saved[0]
		}
	} else {
		rec, e = a.DB.SaveRecord(r.Context(), record)
	}
	if e != nil {
		if u.Role != "admin" && errors.Is(e, store.ErrInvalid) {
			fail(w, 403, "quota_exceeded", "保存失败，账户资源配额已达上限")
			return
		}
		if errors.Is(e, store.ErrConflict) {
			fail(w, 409, "conflict", "记录已更新，请重试")
		} else {
			fail(w, 500, "storage_error", "保存失败")
		}
		return
	}
	if c == "servers" && !exists {
		_, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_agentCredentials", ID: id, Data: map[string]any{"serverToken": newID() + newID(), "agentToken": newID() + newID()}})
		if e != nil {
			fail(w, 500, "credentials_error", "服务器已保存，但接入凭据生成失败，请重试接入配置")
			return
		}
	}
	a.audit(r.Context(), u, "record.save", c+"/"+id, map[string]any{"version": rec.Version})
	if c == "policies" || c == "rules" {
		_, _ = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_documentVersions", ID: newID(), OwnerID: rec.OwnerID, Data: map[string]any{"documentId": rec.ID, "collection": c, "version": rec.Version, "content": rec.Data["content"], "script": rec.Data["script"]}})
	}
	if c == "subscriptions" || c == "plans" || c == "members" || c == "inbounds" {
		a.reconcileUsers(r.Context(), u)
	}
	respond(w, 200, map[string]any{"row": rowOf(rec, c == "subscriptions")})
}
func (a *App) prepareMember(r *http.Request, id string, row map[string]any, exists bool) (store.User, error) {
	application := text(row, "application")
	if exists {
		previous, err := a.DB.GetRecord(r.Context(), "members", id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.User{}, err
		}
		old := defaultText(previous.Data, "application", "aswired")
		if application == "" {
			application = old
		}
		if application != old {
			return store.User{}, errors.New("账户类型创建后不可切换，请创建不同用户名的账户")
		}
	}
	if application == "" {
		application = "aswired"
	}
	if application != "aswired" && application != "komari" {
		return store.User{}, errors.New("无效的账户类型")
	}
	row["application"] = application
	username := strings.TrimSpace(text(row, "username"))
	if username == "" {
		username = strings.TrimSpace(text(row, "name"))
	}
	role := "user"
	if text(row, "role") == "admin" || text(row, "role") == "管理员" {
		role = "admin"
	}
	if text(row, "role") != "" && text(row, "role") != "user" && text(row, "role") != "成员" && text(row, "role") != "普通用户" && role != "admin" {
		return store.User{}, errors.New("角色仅支持管理员或成员")
	}
	if application == "komari" && role != "user" {
		return store.User{}, errors.New("探针账户不能同时拥有 ASWired 管理员权限")
	}
	var u store.User
	var e error
	if exists {
		u, e = a.DB.UserByID(r.Context(), id)
		if e != nil {
			return store.User{}, e
		}
	} else {
		u = store.User{ID: id, TokenVersion: 1}
	}
	password := text(row, "password")
	if !exists && password == "" {
		return store.User{}, errors.New("创建账户需要至少12字节的初始密码")
	}
	if password != "" {
		if e = validCredentials(username, password); e != nil {
			return store.User{}, e
		}
		u.PasswordHash, e = auth.HashPassword(password)
		if e != nil {
			return store.User{}, e
		}
		if exists {
			u.TokenVersion++
		}
	}
	disabled := text(row, "status") == "暂停" || text(row, "status") == "停用"
	if exists && u.Role == "admin" && (role != "admin" || disabled) {
		users, e := a.DB.ListUsers(r.Context())
		if e != nil {
			return store.User{}, e
		}
		count := 0
		for _, other := range users {
			if other.Role == "admin" && !other.Disabled && other.ID != u.ID {
				count++
			}
		}
		if count == 0 {
			return store.User{}, errors.New("不能停用或降级最后一个管理员")
		}
	}
	u.Username = username
	u.Role = role
	if role == "admin" && !a.permittedAdmin(u) {
		return store.User{}, errors.New("该用户名未在 ASWired 管理员名单中")
	}
	u.Disabled = disabled

	delete(row, "password")
	row["username"] = username
	row["role"] = map[string]string{"admin": "管理员", "user": "成员"}[role]
	return u, nil
}
func (a *App) validateRecord(r *http.Request, c, id string, row map[string]any, exists bool) error {
	if c == "certificates" || c == "dnsProviders" {
		return a.validateCertificateRecord(r.Context(), c, row)
	}
	if c == "relays" {
		return a.validateRelay(r.Context(), id, row)
	}
	if c == "schedules" {
		return validateSchedule(row)
	}
	for _, key := range []string{"limit", "cost", "price", "speed", "ipLimit", "deviceLimit"} {
		if v, ok := row[key]; ok && v != nil {
			switch v.(type) {
			case float64, int, int64, json.Number:
			default:
				return fmt.Errorf("%s须为非负数字", key)
			}
			n := number(row, key)
			if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
				return fmt.Errorf("%s须为非负数字", key)
			}
		}
	}
	if c == "nodes" {
		previous, _ := a.DB.GetRecord(r.Context(), c, id)
		managed := exists && boolean(previous.Data, "managedInbound")
		if managed {
			// A managed node is a projection. Accept display edits only; update
			// connection configuration and status through its authoritative inbound.
			for key, value := range row {
				switch key {
				case "name", "tags", "description", "region", "weight", "visible", "sortOrder":
				default:
					before, _ := json.Marshal(previous.Data[key])
					after, _ := json.Marshal(value)
					if string(before) != string(after) {
						return errors.New("受管节点连接配置与状态请通过关联入站修改")
					}
				}
			}
			return nil
		}
		if boolean(row, "managedInbound") || text(row, "inboundId") != "" {
			return errors.New("不能手动创建受管节点身份，请创建入站")
		}
		if exists && disabledStatus(row) {
			if _, err := normalizedProxyNode(previous.Data, !managed); err != nil && legacyProxyUnchanged(row, previous.Data) {
				return nil
			}
		}
		normalized, err := normalizedProxyNode(row, !managed)
		if err != nil {
			return err
		}
		clear(row)
		for key, value := range normalized {
			row[key] = value
		}
	}
	if c == "servers" {
		if strings.TrimSpace(text(row, "address")) == "" {
			return errors.New("请填写服务器地址")
		}
		if !exists {
			row["status"] = "待接入"
		}
		if row["xray_mode"] == nil {
			row["xray_mode"] = "embedded"
		}
		mode := text(row, "xray_mode")
		if mode != "embedded" {
			return errors.New("当前仅支持内嵌 Xray (embedded)，请重新生成接入配置")
		}
		if !nativeServer(store.Record{Data: row}) {
			return errUnsupportedServerConnection
		}
		if strings.TrimSpace(text(row, "connection")) == "" {
			row["connection"] = "自动"
		}
		row["connection"] = serverConnectionLabel(serverConnectionMode(store.Record{Data: row}))
		if raw, ok := row["agentPort"]; ok && raw != nil && raw != "" {
			port := number(row, "agentPort")
			if port < 1 || port > 65535 || port != float64(int(port)) {
				return errors.New("Agent 管理端口须为 1–65535 的整数")
			}
		}
		if address := text(row, "agentUrl"); address != "" {
			if err := validateAgentURL(address); err != nil {
				return err
			}
		}
		delete(row, "activeConnection")
		delete(row, "appliedConnection")
		delete(row, "connectionSwitchSupported")
		row["managementMode"] = "agent"
		row["probeSource"] = "komari"
		row["komariUUID"] = strings.TrimSpace(text(row, "komariUUID"))
		if uuid := text(row, "komariUUID"); uuid != "" {
			servers, err := a.DB.ListRecords(r.Context(), "servers", "")
			if err != nil {
				return err
			}
			for _, server := range servers {
				if server.ID != id && text(server.Data, "komariUUID") == uuid {
					return errors.New("Komari UUID 已绑定其他服务器")
				}
			}
		}
		delete(row, "connectionError")
	}
	if c == "plans" {
		if row["nodeIds"] == nil {
			row["nodeIds"] = []any{}
		}
		if row["cycleDays"] == nil {
			row["cycleDays"] = 30
		}
		if row["directionFactor"] == nil {
			row["directionFactor"] = 1
		}
		if err := a.validatePlanManagement(r.Context(), row); err != nil {
			return err
		}
	}
	if c == "plans" || c == "subscriptions" {
		if err := validateCyclePolicy(row); err != nil {
			return err
		}
	}
	if c == "inbounds" || c == "outbounds" {
		server, e := a.resolve(r, "servers", text(row, "serverId"), text(row, "server"))
		if e != nil {
			return errors.New("请选择有效服务器")
		}
		row["serverId"] = server.ID
		row["server"] = text(server.Data, "name")
		if text(row, "tag") == "" {
			return errors.New("请填写入站/出站标识")
		}
		if c == "outbounds" {
			previous, _ := a.DB.GetRecord(r.Context(), c, id)
			if !(exists && disabledStatus(row) && validateRealityOutbound(previous.Data) != nil && legacyProxyUnchanged(row, previous.Data)) {
				if err := validateRealityOutbound(row); err != nil {
					return err
				}
			}
		}
		if c == "inbounds" {
			retired, err := a.DB.ListRecords(r.Context(), "_deletedManagedInbounds", "")
			if err != nil {
				return err
			}
			for _, deleted := range retired {
				if text(deleted.Data, "serverId") == server.ID && text(deleted.Data, "tag") == text(row, "tag") {
					return errors.New("此标识属于已删除入站，请使用新标识以防旧任务重放")
				}
			}
			if exists && disabledStatus(row) {
				previous, err := a.DB.GetRecord(r.Context(), c, id)
				if err == nil && validateManagedInboundProfile(previous.Data) != nil {
					return nil
				}
			}
			if !exists {
				if text(row, "protocol") == "" {
					row["protocol"] = "VLESS"
				}
				if text(row, "transport") == "" {
					row["transport"] = "TCP / Reality"
				}
			}
			if err := validateManagedInboundProfile(row); err != nil {
				return err
			}
			if !auxiliaryProtocol(row) {
				if _, err := compileInbound(row, nil); err != nil {
					return err
				}
			}
			if _, security := inboundTransport(row); security == "reality" {
				row["protocol"] = "VLESS"
				row["transport"] = "TCP / Reality"
			}
			port := number(row, "port")
			if port < 1 || port > 65535 || math.Trunc(port) != port {
				return errors.New("端口须为1至65535整数")
			}
			others, e := a.DB.ListRecords(r.Context(), c, "")
			if e != nil {
				return e
			}
			for _, other := range others {
				if other.ID != id && text(other.Data, "serverId") == server.ID && (number(other.Data, "port") == port || text(other.Data, "tag") == text(row, "tag")) {
					return errors.New("该服务器端口或标识已被占用")
				}
			}
			if strings.Contains(strings.ToLower(text(row, "transport")), "reality") {
				raw, e := base64.RawURLEncoding.DecodeString(strings.TrimSpace(text(row, "privateKey")))
				if e != nil || len(raw) != 32 {
					return errors.New("Reality私钥必须为32字节X25519密钥")
				}
				key, e := ecdh.X25519().NewPrivateKey(raw)
				if e != nil {
					return errors.New("Reality私钥无效")
				}
				row["publicKey"] = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
				ids := stringList(row["shortIds"])
				if len(ids) == 0 {
					ids = stringList(row["shortId"])
				}
				if len(ids) == 0 && !boolean(row, "allowEmptyShortId") {
					return errors.New("请设置Reality Short ID")
				}
				for _, sid := range ids {
					if len(sid) > 16 || len(sid)%2 != 0 {
						return errors.New("Short ID须为最多16位偶数长度十六进制")
					}
					if _, e := hex.DecodeString(sid); e != nil {
						return errors.New("Short ID包含非法字符")
					}
				}
				row["shortIds"] = ids
			}
		}
	}
	return nil
}
func stringList(v any) []string {
	out := []string{}
	switch vv := v.(type) {
	case []any:
		for _, x := range vv {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		return vv
	case string:
		for _, s := range strings.FieldsFunc(vv, func(r rune) bool { return r == ',' || r == '\n' || r == '，' }) {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
func (a *App) resolve(r *http.Request, c, id, name string) (store.Record, error) {
	if id != "" {
		return a.DB.GetRecord(r.Context(), c, id)
	}
	rows, e := a.DB.ListRecords(r.Context(), c, "")
	if e != nil {
		return store.Record{}, e
	}
	var found *store.Record
	for _, rec := range rows {
		if text(rec.Data, "name") == name || rec.ID == name {
			if found != nil {
				return store.Record{}, errors.New("名称不唯一，请使用ID")
			}
			copy := rec
			found = &copy
		}
	}
	if found == nil {
		return store.Record{}, store.ErrNotFound
	}
	return *found, nil
}
func (a *App) delete(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	c, id := r.PathValue("collection"), r.PathValue("id")
	if c == "policies" && u.Role == "admin" {
		templateMu.Lock()
		defer templateMu.Unlock()
		if err := a.templateDeleteCheck(r.Context(), id); err != nil {
			fail(w, 409, "in_use", err.Error())
			return
		}
	}
	if u.Role == "admin" && (c == "certificates" || c == "dnsProviders") {
		certificateMu.Lock()
		defer certificateMu.Unlock()
		if err := a.certificateReferenceCheck(r.Context(), c, id); err != nil {
			fail(w, 409, "in_use", err.Error())
			return
		}
	}
	if u.Role != "admin" && (c == "nodes" || adminOnlyCollection(c)) {
		fail(w, 403, "forbidden", "需要管理员权限")
		return
	}
	if c == "tasks" || c == "audit" {
		a.deleteLog(w, r)
		return
	}
	if !allowedCollection(c) {
		fail(w, 404, "unknown_collection", "该资源不存在")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), c, id)
	if e != nil {
		fail(w, 404, "not_found", "记录不存在")
		return
	}
	if u.Role != "admin" && (!memberResource(c) || rec.OwnerID != u.ID) {
		fail(w, 403, "forbidden", "只能删除自己的外部资源")
		return
	}
	if c == "inbounds" || c == "nodes" && boolean(rec.Data, "managedInbound") {
		a.deleteManagedInbound(w, r, rec)
		return
	}
	if c == "servers" || c == "plans" {
		for _, dependent := range []string{"inbounds", "outbounds", "subscriptions"} {
			rows, e := a.DB.ListRecords(r.Context(), dependent, "")
			if e != nil {
				fail(w, 500, "storage_error", "引用检查失败")
				return
			}
			for _, row := range rows {
				if (c == "servers" && text(row.Data, "serverId") == id) || (c == "plans" && text(row.Data, "planId") == id) {
					fail(w, 409, "in_use", "该资源仍被使用，请先处理关联记录")
					return
				}
			}
		}
	}
	if c == "members" {
		if id == u.ID {
			fail(w, 409, "self_delete", "不能删除当前登录账户")
			return
		}
		if e = a.DB.DeleteMember(r.Context(), id); e != nil {
			fail(w, 409, "user_in_use", "账户删除失败")
			return
		}
	}
	if c == "inbounds" {
		if e = a.rememberManagedInboundTags(r.Context(), rec); e != nil {
			fail(w, 500, "storage_error", "旧入站任务归属保存失败，请重试")
			return
		}
	}
	if c != "members" {
		if e = a.DB.DeleteRecord(r.Context(), c, id); e != nil {
			fail(w, 500, "storage_error", "删除失败")
			return
		}
	}
	if c == "servers" {
		_ = a.DB.DeleteRecord(r.Context(), "_agentCredentials", id)
		_ = a.DB.DeleteRecord(r.Context(), "_xrayCache", id)
	}
	a.audit(r.Context(), u, "record.delete", c+"/"+id, nil)
	if c == "inbounds" || c == "outbounds" {
		_, _ = a.queueCompile(r.Context(), u, text(rec.Data, "serverId"))
	}
	if c == "members" || c == "subscriptions" {
		a.reconcileUsers(r.Context(), u)
	}
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) settingsMap(r *http.Request) map[string]any {
	defaults := map[string]any{"workspace": "ASWired", "timezone": "Asia/Shanghai", "probePublicEnabled": false, "showCPU": true, "showMemory": true, "showTraffic": true, "probeProvider": "Komari", "probeVersion": "1.2.5-fix2", "release": "稳定版", "clientCompatibility": true}
	var saved map[string]any
	if a.DB.GetSetting(r.Context(), "settings", &saved) == nil {
		for k, v := range saved {
			defaults[k] = v
		}
	}
	if current(r).Role != "admin" {
		return map[string]any{"workspace": defaults["workspace"], "timezone": defaults["timezone"]}
	}
	defaults["probeProvider"] = "Komari"
	defaults["komariAutoSync"] = true
	for _, key := range []string{"telegramToken", "probeApiKey", "webhookSecret", "smtpPassword", "dnsToken", "backupSecret", "probeAccessKey"} {
		if _, ok := defaults[key]; ok {
			defaults[key] = ""
			defaults[key+"Configured"] = true
		}
	}
	defaults["theme"] = "dark"
	return settingsProjection(defaults)
}
func (a *App) settingsGet(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]any{"settings": a.settingsMap(r)})
}
func (a *App) settingsPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Settings map[string]any `json:"settings"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Settings == nil {
		fail(w, 400, "invalid_settings", "缺少设置")
		return
	}
	var old map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &old)
	for _, key := range []string{"telegramToken", "probeApiKey", "webhookSecret", "smtpPassword", "dnsToken", "backupSecret", "probeAccessKey"} {
		if text(in.Settings, key) == "" && old != nil {
			if v, ok := old[key]; ok {
				in.Settings[key] = v
			}
		}
	}
	in.Settings["theme"] = "dark"
	in.Settings["probeVersion"] = "1.2.5-fix2"
	in.Settings["probeProvider"] = "Komari"
	in.Settings["komariAutoSync"] = true
	preserveSettingsSecrets(in.Settings, old)
	if e := validateLimitConfiguration(in.Settings); e != nil {
		fail(w, 400, "invalid_limits", e.Error())
		return
	}
	if backup, ok := in.Settings["remoteBackup"].(map[string]any); ok {
		if e := validateBackupRetention(backup); e != nil {
			fail(w, 400, "invalid_backup_retention", e.Error())
			return
		}
	}
	if e := validateEntrySettings(in.Settings); e != nil {
		fail(w, 400, "invalid_settings", e.Error())
		return
	}
	if e := a.DB.SetSetting(r.Context(), "settings", in.Settings); e != nil {
		fail(w, 500, "storage_error", "设置保存失败")
		return
	}
	a.audit(r.Context(), current(r), "settings.save", "settings", nil)
	respond(w, 200, map[string]any{"settings": a.settingsMap(r)})
}
func settingsProjection(raw map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range raw {
		if secrets[k] {
			out[k] = ""
			out[k+"Configured"] = v != ""
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = settingsProjection(nested)
		} else {
			out[k] = v
		}
	}
	return out
}
func preserveSettingsSecrets(next, old map[string]any) {
	for k, v := range next {
		if strings.HasSuffix(k, "Configured") {
			delete(next, k)
			continue
		}
		if secrets[k] && v == "" && old != nil {
			next[k] = old[k]
		}
		if nested, ok := v.(map[string]any); ok {
			previous, _ := old[k].(map[string]any)
			preserveSettingsSecrets(nested, previous)
		}
	}
}
func taskRow(t store.Task) map[string]any {
	status := map[string]string{"queued": "待下发", "running": "执行中", "success": "成功", "failed": "失败", "unsupported": "不支持", "unknown": "结果未明", "superseded": "已撤回"}[t.Status]
	if status == "" {
		status = t.Status
	}
	var result map[string]any
	_ = json.Unmarshal(t.Result, &result)
	var input map[string]any
	if t.Kind == "certificate.deploy" {
		_ = json.Unmarshal(t.Input, &input)
		input, _ = input["params"].(map[string]any)
	}
	serial := ""
	if block, _ := pem.Decode([]byte(text(input, "certificate"))); block != nil {
		if certificate, err := x509.ParseCertificate(block.Bytes); err == nil {
			serial = certificate.SerialNumber.String()
		}
	}
	return map[string]any{"certificateSerial": serial, "certificateId": text(input, "name"), "id": t.ID, "name": t.Kind, "target": t.ServerID, "type": t.Kind, "status": status, "created": t.CreatedAt.Format(time.RFC3339), "updated": t.UpdatedAt.Format(time.RFC3339), "duration": t.UpdatedAt.Sub(t.CreatedAt).Round(time.Millisecond).String(), "revision": t.ID, "steps": "接收,执行,结果验证", "canDelete": taskLogDeleteReason(t, time.Now()) == "", "deleteReason": taskLogDeleteReason(t, time.Now()), "error": t.Error, "result": sanitize(result)}
}
