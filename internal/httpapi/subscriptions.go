package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/dop251/goja"
	"gopkg.in/yaml.v3"
)

const gib = float64(1024 * 1024 * 1024)

func credentialUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func disabledStatus(row map[string]any) bool {
	switch strings.ToLower(text(row, "status")) {
	case "停用", "暂停", "禁用", "已停用", "草稿", "disabled", "inactive":
		return true
	}
	return boolean(row, "disabled")
}
func dateTime(raw string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02"} {
		var t time.Time
		var e error
		if layout == "2006-01-02" {
			t, e = time.ParseInLocation(layout, raw, time.FixedZone("Asia/Shanghai", 8*3600))
		} else {
			t, e = time.Parse(layout, raw)
		}
		if e == nil {
			if layout == "2006-01-02" {
				return t.Add(24 * time.Hour)
			}
			return t
		}
	}
	return time.Time{}
}

func (a *App) prepareSubscription(r *http.Request, id string, row map[string]any, exists bool) (string, error) {
	if err := validateLimitConfiguration(row); err != nil {
		return "", err
	}
	memberID := text(row, "memberId")
	var user store.User
	var err error
	if memberID != "" {
		user, err = a.DB.UserByID(r.Context(), memberID)
	} else {
		member := text(row, "member")
		user, err = a.DB.UserByUsername(r.Context(), member)
		if err != nil {
			rec, e := a.resolve(r, "members", "", member)
			if e == nil {
				user, err = a.DB.UserByID(r.Context(), rec.ID)
			}
		}
	}
	if err != nil || user.ID == "" {
		return "", errors.New("请选择存在的成员账户")
	}
	plan, err := a.resolve(r, "plans", text(row, "planId"), text(row, "plan"))
	if err != nil {
		return "", errors.New("请选择有效套餐")
	}
	if disabledStatus(plan.Data) {
		return "", errors.New("该套餐尚未启用")
	}
	if expires := text(row, "expires"); expires != "" && dateTime(expires).IsZero() {
		return "", errors.New("到期时间格式无效")
	}
	for _, cidr := range stringList(row["whitelist"]) {
		if cidr == "未设置" {
			continue
		}
		if _, _, e := net.ParseCIDR(cidr); e != nil && net.ParseIP(cidr) == nil {
			return "", errors.New("白名单应为IP或CIDR网段")
		}
	}
	row["memberId"] = user.ID
	row["member"] = user.Username
	row["planId"] = plan.ID
	row["plan"] = text(plan.Data, "name")
	if exists {
		old, e := a.DB.GetRecord(r.Context(), "subscriptions", id)
		if e != nil {
			return "", e
		}
		if old.OwnerID != user.ID || text(old.Data, "planId") != plan.ID {
			return "", errors.New("已有实例不能更换成员或套餐，请分配新的实例")
		}
		for _, key := range []string{"token", "shortCode", "credentialUUID", "credentialPassword", "credentialEmail", "usedBytes", "uploadBytes", "downloadBytes", "used", "cycleStart", "cycleEnd", "accountingGap", "_cyclePolicyHash"} {
			row[key] = old.Data[key]
		}
	} else {
		row["token"] = newID() + newID()
		row["shortCode"] = newID()
		row["credentialUUID"] = credentialUUID()
		row["credentialPassword"] = newID() + newID()
		row["credentialEmail"] = "aswired-" + id + "@subscription"
		now := time.Now().UTC()
		days := int(number(plan.Data, "cycleDays"))
		if days < 1 {
			days = 30
		}
		if days > 3660 {
			return "", errors.New("套餐周期不能超过3660天")
		}
		row["cycleStart"] = now.Format(time.RFC3339Nano)
		row["cycleEnd"] = cycleStamp(nextCycleEnd(cyclePolicy(plan.Data, row), now))
		row["_cyclePolicyHash"] = cyclePolicyDigest(cyclePolicy(plan.Data, row))
		row["usedBytes"] = float64(0)
		row["uploadBytes"] = float64(0)
		row["downloadBytes"] = float64(0)
		row["used"] = float64(0)
		if _, ok := row["limit"]; !ok {
			row["limit"] = number(plan.Data, "limit")
		}
	}
	if text(row, "status") == "" {
		row["status"] = "启用"
	}
	row["subscriptionURL"] = strings.TrimRight(a.Config.PublicURL, "/") + "/api/clash/subscribe?token=" + url.QueryEscape(text(row, "token")) + "&format=clash"
	return user.ID, nil
}

func (a *App) subscriptionActive(ctx context.Context, sub store.Record) error {
	if disabledStatus(sub.Data) {
		return errors.New("订阅已停用")
	}
	user, err := a.DB.UserByID(ctx, sub.OwnerID)
	if err != nil || user.Disabled {
		return errors.New("成员账户已停用")
	}
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil || disabledStatus(plan.Data) {
		return errors.New("套餐不可用")
	}
	if exp := dateTime(text(sub.Data, "expires")); !exp.IsZero() && !time.Now().Before(exp) {
		return errors.New("订阅已到期")
	}
	used, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil {
		return err
	}
	if limit := number(sub.Data, "limit"); limit > 0 && used >= limit*gib {
		if quotaPolicy(sub.Data, plan.Data) <= 0 {
			return errors.New("套餐流量已用尽")
		}
	}
	return nil
}

func (a *App) eligibleNodes(ctx context.Context, sub store.Record) ([]store.Record, error) {
	records, err := a.subscriptionCandidates(ctx, sub)
	if err != nil {
		return nil, err
	}
	result := []store.Record{}
	for _, record := range records {
		if _, err := a.realitySubscriptionNode(ctx, record, sub); err == nil {
			result = append(result, record)
		}
	}
	return result, nil
}

func (a *App) subscriptionCandidates(ctx context.Context, sub store.Record) ([]store.Record, error) {
	if err := a.subscriptionActive(ctx, sub); err != nil {
		return []store.Record{}, err
	}
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, id := range stringList(plan.Data["nodeIds"]) {
		allowed[id] = true
	}
	subAllowed := map[string]bool{}
	for _, id := range stringList(sub.Data["nodeIds"]) {
		subAllowed[id] = true
	}
	nodes, err := a.DB.ListRecords(ctx, "nodes", "")
	if err != nil {
		return nil, err
	}
	result := []store.Record{}
	over, throttle, err := a.quotaOutcome(ctx, sub)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		if over && throttle > 0 && !a.serverSupportsThrottle(text(node.Data, "serverId")) {
			continue
		}
		private := node.OwnerID != "" && node.OwnerID == sub.OwnerID
		if private && sub.Data["includePrivateNodes"] == false {
			continue
		}
		if disabledStatus(node.Data) || len(allowed) > 0 && !allowed[node.ID] || len(subAllowed) > 0 && !subAllowed[node.ID] {
			continue
		}
		if node.OwnerID != "" && node.OwnerID != sub.OwnerID {
			continue
		}
		if sourceID := text(node.Data, "sourceId"); sourceID != "" {
			source, err := a.DB.GetRecord(ctx, "sources", sourceID)
			if err != nil || disabledStatus(source.Data) || source.OwnerID != "" && source.OwnerID != sub.OwnerID {
				continue
			}
		}
		if boolean(node.Data, "managedInbound") {
			over, err := a.planNodeQuotaExceeded(ctx, sub, plan.Data, node.ID, text(node.Data, "inboundId"))
			if err != nil {
				return nil, err
			}
			if over {
				continue
			}
		}
		if names, ok := plan.Data["nodeNames"].(map[string]any); ok {
			if name := strings.TrimSpace(text(names, node.ID)); name != "" {
				node.Data = clone(node.Data)
				node.Data["name"] = name
			}
		}
		result = append(result, node)
	}
	return result, nil
}

func (a *App) refreshInboundNodes(ctx context.Context) error {
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return err
	}
	active := map[string]bool{}
	for _, inbound := range inbounds {
		server, err := a.DB.GetRecord(ctx, "servers", text(inbound.Data, "serverId"))
		if err != nil {
			continue
		}
		id := "inbound-" + inbound.ID
		active[id] = true
		old, _ := a.DB.GetRecord(ctx, "nodes", id)
		row := clone(inbound.Data)
		for _, key := range []string{"privateKey", "private_key", "realitySettings", "streamSettings", "settings", "config", "password", "clients"} {
			delete(row, key)
		}
		row["inboundId"] = inbound.ID
		row["serverId"] = server.ID
		row["host"] = text(server.Data, "publicAddress")
		if row["host"] == "" {
			row["host"] = text(server.Data, "address")
		}
		if strings.TrimSpace(text(row, "region")) == "" {
			if region := strings.TrimSpace(text(server.Data, "region")); region != "" {
				row["region"] = region
			} else {
				host := text(server.Data, "publicAddress")
				if host == "" {
					host = text(server.Data, "address")
				}
				if country := a.lookupHostCountry(ctx, host); country != "" {
					row["region"] = country
				}
			}
		}
		row["source"] = "自建 / " + text(server.Data, "name")
		row["managedInbound"] = true
		if err := validateManagedInboundProfile(inbound.Data); err != nil {
			row["status"] = "禁用"
			row["managementError"] = err.Error()
		} else {
			row["network"], row["security"] = inboundTransport(inbound.Data)
		}
		if len(stringList(row["shortIds"])) > 0 {
			row["shortId"] = stringList(row["shortIds"])[0]
		}
		preserveNodeLatency(row, old.Data)
		// Display metadata belongs to the node, not the generated inbound projection.
		for _, key := range []string{"name", "tags", "description", "region", "weight", "visible", "sortOrder"} {
			if value, present := old.Data[key]; present {
				row[key] = value
			}
		}
		if old.ID != "" {
			before, _ := json.Marshal(old.Data)
			after, _ := json.Marshal(row)
			if string(before) == string(after) {
				continue
			}
		}
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: id, Data: row, Version: old.Version}); err != nil {
			return err
		}
	}
	nodes, err := a.DB.ListRecords(ctx, "nodes", "")
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if boolean(node.Data, "managedInbound") && !active[node.ID] {
			if err := a.DB.DeleteRecord(ctx, "nodes", node.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) usersForInbound(ctx context.Context, inbound store.Record) ([]map[string]any, error) {
	users := []map[string]any{}
	if disabledStatus(inbound.Data) {
		return users, nil
	}
	if err := validateManagedInboundProfile(inbound.Data); err != nil {
		return nil, err
	}
	subs, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil {
		return nil, err
	}
	for _, sub := range subs {
		nodes, err := a.eligibleNodes(ctx, sub)
		if err != nil {
			continue
		}
		selected := false
		for _, node := range nodes {
			if text(node.Data, "inboundId") == inbound.ID {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		user := map[string]any{"email": text(sub.Data, "credentialEmail") + "." + inbound.ID, "level": 0}
		switch strings.ToLower(text(inbound.Data, "protocol")) {
		case "vless", "vmess":
			user["id"] = text(sub.Data, "credentialUUID")
			if flow := text(inbound.Data, "flow"); strings.ToLower(text(inbound.Data, "protocol")) == "vless" && flow != "" && flow != "无" {
				user["flow"] = flow
			}
		case "trojan":
			user["password"] = text(sub.Data, "credentialPassword")
		case "socks", "socks5", "http":
			user["password"] = text(sub.Data, "credentialPassword")
		case "hysteria", "hysteria2", "hy2":
			user["auth"] = text(sub.Data, "credentialPassword")
		case "ss", "shadowsocks":
			method := defaultText(inbound.Data, "method", text(inbound.Data, "cipher"))
			switch method {
			case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
			default:
				continue
			}
			user["method"] = method
			user["password"] = text(sub.Data, "credentialPassword")
		case "anytls", "snell":
			user["id"] = text(sub.Data, "credentialUUID")
			user["password"] = text(sub.Data, "credentialPassword")
		default:
			continue
		}
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return text(users[i], "email") < text(users[j], "email") })
	return users, nil
}

func (a *App) reconcileUsers(ctx context.Context, u store.User) {
	if err := a.refreshInboundNodes(ctx); err != nil {
		a.audit(ctx, u, "subscription.reconcile.failed", "", map[string]any{"error": err.Error()})
		return
	}
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		proto := strings.ToLower(text(inbound.Data, "protocol"))
		if proto != "vless" && proto != "vmess" && proto != "trojan" && proto != "hysteria" && proto != "hysteria2" && proto != "hy2" && proto != "ss" && proto != "shadowsocks" && proto != "socks" && proto != "socks5" && proto != "http" {
			continue
		}
		users, err := a.usersForInbound(ctx, inbound)
		if err != nil {
			if validateManagedInboundProfile(inbound.Data) == nil {
				continue
			}
			users = []map[string]any{}
		}
		params := map[string]any{"inbound": text(inbound.Data, "tag"), "users": users}
		if proto == "socks" || proto == "socks5" || proto == "http" {
			a.mu.Lock()
			peer := a.peers[text(inbound.Data, "serverId")]
			supported := peer != nil && peer.Capabilities["managed_account_reload"]
			a.mu.Unlock()
			if !supported {
				continue
			}
		}
		encoded, _ := json.Marshal(params)
		hash := sha256.Sum256(encoded)
		digest := hex.EncodeToString(hash[:])
		stateID := text(inbound.Data, "serverId") + "/" + inbound.ID
		old, _ := a.DB.GetRecord(ctx, "_userSync", stateID)
		if text(old.Data, "digest") == digest {
			task, err := a.DB.GetTask(ctx, text(old.Data, "taskId"))
			if err == nil && (task.Status == "queued" || task.Status == "running" || task.Status == "success") {
				continue
			}
		}
		task, err := a.queue(ctx, u, text(inbound.Data, "serverId"), "core.users.sync", params)
		if err != nil {
			continue
		}
		a.supersedeQueued(ctx, text(old.Data, "taskId"))
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_userSync", ID: stateID, Data: map[string]any{"digest": digest, "taskId": task.ID}, Version: old.Version})
	}
	a.reconcilePolicies(ctx, u)
	a.reconcileAuxiliary(ctx, u)
}

type effectiveLimit struct {
	Value float64
	Set   bool
}

func limitValue(row map[string]any, key string) effectiveLimit {
	if value, exists := row[key]; exists && value != nil {
		switch value.(type) {
		case float64, int, int64, json.Number:
			if n := number(row, key); n >= 0 {
				return effectiveLimit{n, true}
			}
		}
	}
	return effectiveLimit{}
}
func nodeOverride(row map[string]any, serverID, nodeID, key string) effectiveLimit {
	if all, ok := row["nodeLimits"].(map[string]any); ok {
		for _, id := range []string{nodeID, serverID} {
			if item, ok := all[id].(map[string]any); ok {
				if limit := limitValue(item, key); limit.Set {
					return limit
				}
			}
		}
	}
	return effectiveLimit{}
}
func inheritedLimit(member, plan map[string]any, serverID, nodeID, key string) effectiveLimit {
	for _, candidate := range []effectiveLimit{nodeOverride(member, serverID, nodeID, key), limitValue(member, key), nodeOverride(plan, serverID, nodeID, key), limitValue(plan, key)} {
		if candidate.Set {
			return candidate
		}
	}
	return effectiveLimit{0, true}
}
func highestEntitlement(old, next effectiveLimit) effectiveLimit {
	if !old.Set {
		return next
	}
	if old.Value == 0 || next.Value == 0 {
		return effectiveLimit{0, true}
	}
	if next.Value > old.Value {
		return next
	}
	return old
}

type physicalUserPolicy struct {
	UserID                  string
	Emails                  map[string]bool
	Revoked                 map[string]bool
	Speed, Connections, IPs effectiveLimit
	Quotas                  []map[string]any
}

func (a *App) reconcilePolicies(ctx context.Context, actor store.User) {
	subs, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil {
		return
	}
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return
	}
	servers, err := a.DB.ListRecords(ctx, "servers", "")
	if err != nil {
		return
	}
	groups := map[string]map[string]*physicalUserPolicy{}
	for _, server := range servers {
		groups[server.ID] = map[string]*physicalUserPolicy{}
	}
	for _, sub := range subs {
		plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
		if err != nil {
			continue
		}
		member, _ := a.DB.GetRecord(ctx, "members", sub.OwnerID)
		isActive := a.subscriptionActive(ctx, sub) == nil
		overQuota, quotaSpeed, quotaErr := a.quotaOutcome(ctx, sub)
		if quotaErr != nil {
			continue
		}
		a.noteQuotaState(ctx, sub, plan, overQuota, quotaSpeed)
		allowed := map[string]bool{}
		for _, id := range stringList(plan.Data["nodeIds"]) {
			allowed[id] = true
		}
		subAllowed := map[string]bool{}
		for _, id := range stringList(sub.Data["nodeIds"]) {
			subAllowed[id] = true
		}
		for _, inbound := range inbounds {
			serverID := text(inbound.Data, "serverId")
			nodeID := "inbound-" + inbound.ID
			if groups[serverID] == nil || (len(allowed) > 0 && !allowed[nodeID]) || (len(subAllowed) > 0 && !subAllowed[nodeID]) {
				continue
			}
			group := groups[serverID][sub.OwnerID]
			if group == nil {
				group = &physicalUserPolicy{UserID: sub.OwnerID, Emails: map[string]bool{}, Revoked: map[string]bool{}}
				groups[serverID][sub.OwnerID] = group
			}
			email := text(sub.Data, "credentialEmail") + "." + inbound.ID
			nodeOverQuota, nodeQuotaErr := a.planNodeQuotaExceeded(ctx, sub, plan.Data, nodeID, inbound.ID)
			if !isActive || nodeOverQuota || nodeQuotaErr != nil || disabledStatus(inbound.Data) || validateManagedInboundProfile(inbound.Data) != nil || (overQuota && quotaSpeed > 0 && !a.serverSupportsThrottle(serverID)) {
				group.Revoked[email] = true
				continue
			}
			group.Emails[email] = true
			speed := inheritedLimit(member.Data, plan.Data, serverID, nodeID, "speed")
			if overQuota {
				speed = cappedLimit(speed, quotaSpeed)
			}
			group.Speed = highestEntitlement(group.Speed, speed)
			group.Quotas = append(group.Quotas, map[string]any{"subscriptionId": sub.ID, "overQuota": overQuota, "quotaSpeedMbps": quotaSpeed, "entitlementMbps": speed.Value})
			group.Connections = highestEntitlement(group.Connections, inheritedLimit(member.Data, plan.Data, serverID, nodeID, "connectionLimit"))
			group.IPs = highestEntitlement(group.IPs, inheritedLimit(member.Data, plan.Data, serverID, nodeID, "ipLimit"))
		}
	}
	for serverID, users := range groups {
		old, oldErr := a.DB.GetRecord(ctx, "_policySync", serverID)
		if oldErr != nil && !errors.Is(oldErr, store.ErrNotFound) {
			continue
		}
		if previous, ok := old.Data["policies"].([]any); ok {
			for _, raw := range previous {
				policy, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				userID := strings.TrimSuffix(text(policy, "user_id"), "#revoked")
				group := users[userID]
				if group == nil {
					group = &physicalUserPolicy{UserID: userID, Emails: map[string]bool{}, Revoked: map[string]bool{}}
					users[userID] = group
				}
				for _, email := range stringList(policy["emails"]) {
					if !group.Emails[email] {
						group.Revoked[email] = true
					}
				}
			}
		}
		policies := []map[string]any{}
		for _, group := range users {
			active := []string{}
			for email := range group.Emails {
				active = append(active, email)
			}
			sort.Strings(active)
			if len(active) > 0 {
				speed, explanation := a.behaviorEffective(ctx, group.UserID, serverID, group.Speed, time.Now())
				explanation["quotas"] = group.Quotas
				explanation["serverId"] = serverID
				explanation["userId"] = group.UserID
				explanation["enforcementAvailable"] = a.serverSupportsThrottle(serverID)
				explanation["direction"] = "download"
				a.saveEffectiveLimit(ctx, serverID, group.UserID, explanation)
				policies = append(policies, map[string]any{"user_id": group.UserID, "emails": active, "bytes_per_second": int64(speed.Value * 1e6 / 8), "direction": "download", "connection_limit": int64(group.Connections.Value), "ip_limit": int64(group.IPs.Value), "disabled": false})
			}
			revoked := []string{}
			for email := range group.Revoked {
				if !group.Emails[email] {
					revoked = append(revoked, email)
				}
			}
			sort.Strings(revoked)
			if len(revoked) > 0 {
				if len(active) == 0 {
					a.saveEffectiveLimit(ctx, serverID, group.UserID, map[string]any{"serverId": serverID, "userId": group.UserID, "disabled": true, "reason": "no_active_credentials", "effectiveMbps": 0, "quotas": group.Quotas})
				}
				policies = append(policies, map[string]any{"user_id": group.UserID + "#revoked", "emails": revoked, "bytes_per_second": 0, "connection_limit": 0, "ip_limit": 0, "disabled": true})
			}
		}
		sort.Slice(policies, func(i, j int) bool { return text(policies[i], "user_id") < text(policies[j], "user_id") })
		if len(policies) == 0 && old.ID == "" && a.noOtherPolicyTask(ctx, serverID, "") {
			continue
		}
		params := map[string]any{"policies": policies}
		encoded, _ := json.Marshal(params)
		sum := sha256.Sum256(encoded)
		digest := hex.EncodeToString(sum[:])
		if text(old.Data, "digest") == digest {
			task, e := a.DB.GetTask(ctx, text(old.Data, "taskId"))
			if e == nil && (task.Status == "queued" || task.Status == "running" || task.Status == "success" || task.Status == "unsupported" || task.Status == "superseded" && (task.Error == unusedInitialPolicyMessage || task.LogReason == "initial_policy_unused") && a.noOtherPolicyTask(ctx, serverID, task.ID)) {
				continue
			}
		}
		task, e := a.queue(ctx, actor, serverID, "core.policy.apply", params)
		if e != nil {
			continue
		}
		a.supersedeQueued(ctx, text(old.Data, "taskId"))
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_policySync", ID: serverID, Data: map[string]any{"digest": digest, "taskId": task.ID, "policies": policies}, Version: old.Version})
	}
}
func (a *App) supersedeQueued(ctx context.Context, id string) {
	if id == "" {
		return
	}
	task, err := a.DB.GetTask(ctx, id)
	if err == nil && task.Status == "queued" {
		task.Status = "superseded"
		task.Error = "已由较新的完整配置替代，未向节点执行"
		_, _ = a.DB.SaveTask(ctx, task)
	}
}

func (a *App) subscriptionConfig(w http.ResponseWriter, r *http.Request) {
	sub, err := a.DB.GetRecord(r.Context(), "subscriptions", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "订阅不存在")
		return
	}
	if u := current(r); u.Role != "admin" && sub.OwnerID != u.ID {
		fail(w, 403, "forbidden", "无权读取此订阅")
		return
	}
	a.serveSubscription(w, r, sub)
}
func (a *App) subscriptionRotate(w http.ResponseWriter, r *http.Request) {
	sub, err := a.DB.GetRecord(r.Context(), "subscriptions", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "订阅不存在")
		return
	}
	u := current(r)
	if u.Role != "admin" && sub.OwnerID != u.ID {
		fail(w, 403, "forbidden", "无权修改此订阅")
		return
	}
	sub.Data["token"] = newID() + newID()
	sub.Data["shortCode"] = newID()
	sub.Data["subscriptionURL"] = strings.TrimRight(a.Config.PublicURL, "/") + "/api/clash/subscribe?token=" + url.QueryEscape(text(sub.Data, "token")) + "&format=clash"
	sub, err = a.DB.SaveRecord(r.Context(), sub)
	if err != nil {
		fail(w, 409, "conflict", "订阅已更新，请重试")
		return
	}
	a.audit(r.Context(), u, "subscription.token.rotate", sub.ID, nil)
	respond(w, 200, map[string]any{"row": rowOf(sub, true), "token": sub.Data["token"], "url": sub.Data["subscriptionURL"]})
}
func (a *App) publicSubscription(w http.ResponseWriter, r *http.Request) {
	a.subscriptionByCredential(w, r, "token", r.URL.Query().Get("token"))
}
func (a *App) shortSubscription(w http.ResponseWriter, r *http.Request) {
	a.subscriptionByCredential(w, r, "shortCode", r.PathValue("code"))
}
func (a *App) subscriptionByCredential(w http.ResponseWriter, r *http.Request, key, credential string) {
	if len(credential) < 20 || len(credential) > 200 {
		a.securityEvent(r, "subscription.probe", "无效订阅凭据")
		fail(w, 401, "invalid_subscription", "订阅凭据无效")
		return
	}
	subs, err := a.DB.ListRecords(r.Context(), "subscriptions", "")
	if err != nil {
		fail(w, 503, "storage_error", "订阅暂不可用")
		return
	}
	for _, sub := range subs {
		if constant(text(sub.Data, key), credential) {
			a.serveSubscription(w, r, sub)
			return
		}
	}
	a.securityEvent(r, "subscription.probe", "订阅凭据不匹配")
	fail(w, 401, "invalid_subscription", "订阅凭据无效")
}

func (a *App) serveSubscription(w http.ResponseWriter, r *http.Request, sub store.Record) {
	if err := a.subscriptionActive(r.Context(), sub); err != nil {
		fail(w, 403, "subscription_inactive", err.Error())
		return
	}
	whitelist := stringList(sub.Data["whitelist"])
	if len(whitelist) > 0 && whitelist[0] != "未设置" {
		host := requestIP(r)
		ip := net.ParseIP(host)
		allowed := false
		for _, entry := range whitelist {
			if _, network, e := net.ParseCIDR(entry); e == nil && network.Contains(ip) {
				allowed = true
			}
			if peer := net.ParseIP(entry); peer != nil && peer.Equal(ip) {
				allowed = true
			}
		}
		if !allowed {
			fail(w, 403, "subscription_ip_denied", "访问地址不在订阅白名单内")
			return
		}
	}
	format := normalizeFormat(r.URL.Query().Get("format"))
	var templateErr error
	sub, templateErr = a.requestedTemplate(r, sub, format)
	if templateErr != nil {
		fail(w, 403, "template_denied", templateErr.Error())
		return
	}
	nodes, err := a.subscriptionCandidates(r.Context(), sub)
	if err != nil {
		fail(w, 403, "subscription_inactive", err.Error())
		return
	}
	output, contentType, skipped, err := a.renderSubscription(r.Context(), sub, nodes, format)
	if err != nil {
		fail(w, 422, "incompatible_config", err.Error())
		return
	}
	_, up, down, _ := a.subscriptionUsage(r.Context(), sub)
	a.grantEntry(w, r)
	header := fmt.Sprintf("upload=%.0f; download=%.0f; total=%.0f", up, down, number(sub.Data, "limit")*gib)
	if expiry := dateTime(text(sub.Data, "expires")); !expiry.IsZero() {
		header += fmt.Sprintf("; expire=%d", expiry.Unix())
	}
	w.Header().Set("Subscription-Userinfo", header)
	w.Header().Set("Profile-Update-Interval", "6")
	w.Header().Set("X-ASWired-Skipped-Nodes", strconv.Itoa(skipped))
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(200)
	_, _ = w.Write([]byte(output))
}

func normalizeFormat(format string) string {
	switch strings.ToLower(strings.ReplaceAll(format, " ", "")) {
	case "", "clash", "clashmeta", "mihomo":
		return "clash"
	case "sing-box", "singbox":
		return "singbox"
	case "quantumultx", "qx":
		return "qx"
	default:
		return strings.ToLower(format)
	}
}

type clientNode struct {
	Name, Protocol, Host, UUID, Password, Method, Security, SNI, Network, Path, HostHeader, PublicKey, ShortID, Flow, ServiceName string
	Port                                                                                                                          int
	Obfs, ObfsPassword, Plugin, PluginSpec, Congestion, UDPRelay                                                                  string
	PluginOptions                                                                                                                 map[string]any
	ALPN                                                                                                                          []string
	ZeroRTT, Insecure                                                                                                             bool
	TCPOnly                                                                                                                       bool
	UnsupportedFields                                                                                                             []string
	SnellVersion                                                                                                                  int
	Username, Fingerprint, PrivateKey, PreSharedKey, LocalIP, LocalIPv6                                                           string
	AlterID, MTU                                                                                                                  int
	Up, Down                                                                                                                      float64
	Reserved                                                                                                                      []any
}

func clientNodeFor(rec store.Record, sub store.Record) (clientNode, error) {
	row := clone(rec.Data)
	n := clientNode{Name: text(row, "name"), Protocol: strings.ToLower(text(row, "protocol")), Host: text(row, "host"), Port: int(number(row, "port")), UUID: text(row, "uuid"), Password: text(row, "password"), Method: text(row, "method"), Security: text(row, "security"), SNI: text(row, "sni"), Network: text(row, "network"), Path: text(row, "path"), HostHeader: text(row, "hostHeader"), PublicKey: text(row, "publicKey"), ShortID: text(row, "shortId"), Flow: text(row, "flow"), ServiceName: text(row, "serviceName")}
	n.Username, n.Fingerprint = text(row, "username"), defaultText(row, "fingerprint", text(row, "client-fingerprint"))
	n.PrivateKey, n.PreSharedKey, n.LocalIP, n.LocalIPv6 = text(row, "privateKey"), text(row, "preSharedKey"), text(row, "ip"), text(row, "ipv6")
	if reserved, ok := row["reserved"].([]any); ok {
		for _, value := range reserved {
			n.Reserved = append(n.Reserved, int(number(map[string]any{"byte": value}, "byte")))
		}
	}
	n.AlterID, n.MTU, n.Up, n.Down = int(number(row, "alterId")), int(number(row, "mtu")), number(row, "up"), number(row, "down")
	n.SnellVersion = int(number(row, "snellVersion"))
	if n.SnellVersion == 0 {
		n.SnellVersion = int(number(row, "version"))
	}
	if n.SnellVersion == 0 {
		n.SnellVersion = 4
	}
	n.Obfs = text(row, "obfs")
	n.ObfsPassword = defaultText(row, "obfsPassword", text(row, "obfs-password"))
	if obfs, ok := row["obfs"].(map[string]any); ok {
		n.Obfs = text(obfs, "type")
		n.ObfsPassword = text(obfs, "password")
		for key, value := range obfs {
			if key != "type" && key != "password" && configuredExtension(value) {
				n.UnsupportedFields = append(n.UnsupportedFields, "obfs."+key)
			}
		}
	}
	n.Plugin = text(row, "plugin")
	n.PluginSpec = text(row, "plugin_opts")
	n.PluginOptions, _ = row["plugin-opts"].(map[string]any)
	if n.PluginOptions == nil {
		n.PluginOptions, _ = row["pluginOptions"].(map[string]any)
	}
	n.Congestion = defaultText(row, "congestionController", defaultText(row, "congestionControl", defaultText(row, "congestion-controller", text(row, "congestion_control"))))
	n.UDPRelay = defaultText(row, "udpRelayMode", defaultText(row, "udp-relay-mode", text(row, "udp_relay_mode")))
	n.ALPN = stringList(row["alpn"])
	n.ZeroRTT = boolean(row, "zero_rtt_handshake") || boolean(row, "reduce-rtt")
	n.Insecure = boolean(row, "skipCertVerify") || boolean(row, "skip-cert-verify") || boolean(row, "insecure")
	if tls, ok := row["tls"].(map[string]any); ok {
		if n.SNI == "" {
			n.SNI = text(tls, "server_name")
		}
		if len(n.ALPN) == 0 {
			n.ALPN = stringList(tls["alpn"])
		}
		n.Insecure = boolean(tls, "insecure")
	}
	for _, key := range []string{"ports", "server_ports", "hop-interval", "hop_interval", "realm-opts", "obfs-opts", "obfs-min-packet-size", "obfs-max-packet-size", "udp_over_stream", "disable-sni", "heartbeat", "heartbeat-interval"} {
		if value, exists := row[key]; exists && configuredExtension(value) {
			n.UnsupportedFields = append(n.UnsupportedFields, key)
		}
	}
	if rawURI := text(row, "uri"); rawURI != "" {
		if uri, err := url.Parse(rawURI); err == nil {
			q := uri.Query()
			if n.Obfs == "" {
				n.Obfs = q.Get("obfs")
			}
			if n.ObfsPassword == "" {
				n.ObfsPassword = q.Get("obfs-password")
			}
			if plugin := q.Get("plugin"); plugin != "" && n.Plugin == "" {
				parts := strings.SplitN(plugin, ";", 2)
				n.Plugin = parts[0]
				if len(parts) == 2 {
					n.PluginSpec = parts[1]
				}
			}
			if n.Protocol == "tuic" && uri.User != nil {
				n.UUID = uri.User.Username()
				n.Password, _ = uri.User.Password()
			}
			if n.Congestion == "" {
				n.Congestion = q.Get("congestion_control")
			}
			if n.UDPRelay == "" {
				n.UDPRelay = q.Get("udp_relay_mode")
			}
			if len(n.ALPN) == 0 {
				n.ALPN = stringList(q.Get("alpn"))
			}
		}
	}
	if n.Name == "" {
		n.Name = rec.ID
	}
	if n.Host == "" {
		n.Host = text(row, "server")
	}
	if n.Method == "" {
		n.Method = text(row, "cipher")
	}
	if uri := text(row, "uri"); uri != "" && n.Host == "" {
		u, e := url.Parse(uri)
		if e != nil {
			return n, e
		}
		n.Protocol = strings.ToLower(u.Scheme)
		n.Host = u.Hostname()
		n.Port, _ = strconv.Atoi(u.Port())
		if u.User != nil {
			n.UUID = u.User.Username()
			n.Password = u.User.Username()
			if n.Protocol == "tuic" {
				n.Password, _ = u.User.Password()
			}
		}
		q := u.Query()
		n.Security = q.Get("security")
		n.Network = q.Get("type")
		n.SNI = q.Get("sni")
		n.PublicKey = q.Get("pbk")
		n.ShortID = q.Get("sid")
		n.Flow = q.Get("flow")
		n.Path = q.Get("path")
		n.ServiceName = q.Get("serviceName")
	}
	if n.Protocol == "shadowsocks" {
		n.Protocol = "ss"
	}
	if n.Protocol == "hysteria2" || n.Protocol == "hy2" {
		n.Protocol = "hysteria2"
	}
	if n.Protocol == "socks" {
		n.Protocol = "socks5"
	}
	if n.Password == "" {
		n.Password = text(row, "psk")
	}
	if (n.Protocol == "hysteria2" || n.Protocol == "tuic") && (n.Network == "hysteria" || n.Network == "quic") {
		n.Network = "tcp"
	}
	transport := strings.ToLower(text(row, "transport"))
	if n.Network == "" {
		n.Network = "tcp"
		switch {
		case strings.Contains(transport, "websocket"):
			n.Network = "ws"
		case strings.Contains(transport, "grpc"):
			n.Network = "grpc"
		case strings.Contains(transport, "xhttp"):
			n.Network = "xhttp"
		case strings.Contains(transport, "mkcp"):
			n.Network = "kcp"
		}
	}
	if n.Security == "" {
		if strings.Contains(transport, "reality") {
			n.Security = "reality"
		} else if strings.Contains(transport, "tls") || n.Protocol == "trojan" {
			n.Security = "tls"
		}
	}
	if n.Flow == "无" {
		n.Flow = ""
	}
	if n.Protocol != "vless" {
		n.Flow = ""
	}
	if names := stringList(n.SNI); len(names) > 0 {
		n.SNI = names[0]
	}
	if (n.Protocol == "hysteria" || n.Protocol == "hysteria2" || n.Protocol == "tuic" || n.Protocol == "anytls") && n.Security == "" {
		n.Security = "tls"
	}
	if n.Path == "" {
		n.Path = "/"
	}
	if text(row, "inboundId") != "" {
		n.TCPOnly = n.Protocol == "socks5" || n.Protocol == "http"
		n.UUID = text(sub.Data, "credentialUUID")
		n.Password = text(sub.Data, "credentialPassword")
		if n.Protocol == "socks5" || n.Protocol == "http" {
			n.Username = text(sub.Data, "credentialEmail") + "." + text(row, "inboundId")
		}
		if n.Protocol == "hysteria2" && len(n.ALPN) == 0 {
			n.ALPN = []string{"h3"}
		}
	}
	if n.Host == "" || n.Port < 1 || n.Port > 65535 || strings.ContainsAny(n.Host, "\r\n,=/\\") {
		return n, errors.New("节点地址或端口不完整")
	}
	if (n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "tuic") && n.UUID == "" {
		return n, errors.New("节点缺少UUID")
	}
	if (n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "hysteria2" || n.Protocol == "tuic" || n.Protocol == "anytls" || n.Protocol == "snell") && n.Password == "" {
		return n, errors.New("节点缺少密码")
	}
	if n.Protocol == "ss" && n.Method == "" {
		return n, errors.New("Shadowsocks节点缺少加密算法")
	}
	if n.Protocol == "vmess" {
		if n.Method == "" {
			n.Method = "auto"
		}
		switch n.Method {
		case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
		default:
			return n, errors.New("VMess 加密算法无效")
		}
		if n.AlterID < 0 || n.AlterID > 65535 {
			return n, errors.New("VMess alterId 无效")
		}
	}
	if n.Protocol == "hysteria" && (n.Up <= 0 || n.Down <= 0) {
		return n, errors.New("Hysteria 需要正数 up/down 带宽（Mbps）")
	}
	if n.Security == "reality" && n.PublicKey == "" {
		return n, errors.New("Reality节点缺少公钥")
	}
	if len(n.UnsupportedFields) > 0 {
		return n, fmt.Errorf("当前输出适配尚不能保留扩展字段: %s", strings.Join(n.UnsupportedFields, ", "))
	}
	if n.Obfs != "" && n.Protocol != "hysteria" && (n.Protocol != "hysteria2" || (n.Obfs != "salamander" && n.Obfs != "gecko") || n.ObfsPassword == "") {
		return n, errors.New("HY2混淆须为具有密码的salamander/gecko，未知混淆不会静默丢弃")
	}
	if n.Plugin != "" {
		if n.Protocol != "ss" {
			return n, errors.New("SIP003插件仅适用于Shadowsocks")
		}
		if err := normalizeSSPlugin(&n); err != nil {
			return n, err
		}
	}
	if n.Congestion != "" && n.Congestion != "cubic" && n.Congestion != "new_reno" && n.Congestion != "bbr" {
		return n, errors.New("TUIC拥塞控制配置无效")
	}
	if n.UDPRelay != "" && n.UDPRelay != "native" && n.UDPRelay != "quic" {
		return n, errors.New("TUIC UDP中继模式无效")
	}
	for _, v := range append([]string{n.Name, n.UUID, n.Username, n.Password, n.Method, n.Security, n.SNI, n.Network, n.Path, n.HostHeader, n.PublicKey, n.ShortID, n.Flow, n.ServiceName, n.ObfsPassword, n.Plugin, n.PluginSpec, n.Fingerprint, n.PrivateKey, n.PreSharedKey}, n.ALPN...) {
		if strings.ContainsAny(v, "\r\n\x00") {
			return n, errors.New("节点字段包含非法换行")
		}
	}
	return n, nil
}

func compatible(n clientNode, format string) bool {
	if n.Username != "" && format != "clash" && format != "singbox" && format != "stash" {
		return false
	}
	if n.Protocol == "socks5" && n.Security == "tls" && format == "singbox" {
		return false
	}
	if n.Protocol == "vmess" && (n.AlterID != 0 || n.Method != "" && n.Method != "auto") && format != "clash" && format != "singbox" && format != "stash" && format != "v2ray" && format != "shadowrocket" {
		return false
	}
	if n.HostHeader != "" && (format == "qx" || format == "loon") {
		return false
	}
	if n.Fingerprint != "" && n.Fingerprint != "chrome" && format != "clash" && format != "singbox" && format != "v2ray" && format != "shadowrocket" {
		return false
	}
	if n.Protocol == "wireguard" {
		return format == "clash" && n.Network == "tcp" && (n.Security == "" || n.Security == "none")
	}
	if n.Protocol == "hysteria" {
		return (format == "clash" || format == "singbox") && n.Network == "tcp" && n.Security == "tls"
	}
	if n.Protocol == "snell" {
		return (n.SnellVersion == 3 || n.SnellVersion == 4) && n.Network == "tcp" && (n.Security == "" || n.Security == "none") && len(n.ALPN) == 0 && !n.Insecure && (format == "clash" || format == "surge")
	}
	if (n.Obfs != "" || n.Plugin != "" || len(n.ALPN) > 0 || n.Insecure) && format != "clash" && format != "singbox" && format != "stash" {
		return false
	}
	if n.Plugin != "" && format == "stash" {
		return false
	}
	if n.Protocol == "ss" && (n.Security != "" && n.Security != "none" || n.Network != "tcp") {
		return false
	}
	if n.Network != "tcp" && n.Network != "ws" && n.Network != "grpc" {
		return false
	}
	switch format {
	case "clash", "singbox":
		return n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "hysteria2" || n.Protocol == "tuic" || n.Protocol == "anytls" || n.Protocol == "socks5" || n.Protocol == "http"
	case "stash":
		return n.Security != "reality" && (n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "socks5" || n.Protocol == "http")
	case "surge", "surfboard":
		return n.Network != "grpc" && n.Security != "reality" && (n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "socks5" || n.Protocol == "http")
	case "loon":
		return n.Network != "grpc" && n.Security != "reality" && n.Flow == "" && (n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "hysteria2" || n.Protocol == "http")
	case "qx":
		return n.Security != "reality" && n.Network != "grpc" && n.Flow == "" && (n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "socks5" || n.Protocol == "http")
	case "egern":
		return n.Network != "grpc" && (n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss" || n.Protocol == "socks5" || n.Protocol == "http")
	case "v2ray", "shadowrocket":
		return n.Protocol == "vless" || n.Protocol == "vmess" || n.Protocol == "trojan" || n.Protocol == "ss"
	}
	return false
}

func (a *App) renderSubscription(ctx context.Context, sub store.Record, records []store.Record, format string) (string, string, int, error) {
	nodes := []clientNode{}
	reasons := []string{}
	names := map[string]int{}
	for _, rec := range records {
		node, e := a.realitySubscriptionNode(ctx, rec, sub)
		if e != nil {
			reasons = append(reasons, text(rec.Data, "name")+": "+e.Error())
			continue
		}
		if !compatible(node, format) {
			reasons = append(reasons, node.Name+": "+incompatibilityReason(node, format))
			continue
		}
		names[node.Name]++
		if names[node.Name] > 1 {
			node.Name += fmt.Sprintf(" (%d)", names[node.Name])
		}
		nodes = append(nodes, node)
	}
	return a.renderClientNodes(ctx, sub, nodes, reasons, format)
}

func (a *App) renderMergedSubscription(ctx context.Context, subs []store.Record, format string) (string, string, int, error) {
	nodes := []clientNode{}
	reasons := []string{}
	owner := ""
	names := map[string]int{}
	for _, sub := range subs {
		if sub.OwnerID == "" || (owner != "" && owner != sub.OwnerID) {
			return "", "", 0, errors.New("合并订阅必须属于同一个账户")
		}
		owner = sub.OwnerID
		if err := a.subscriptionActive(ctx, sub); err != nil {
			reasons = append(reasons, sub.ID+": "+err.Error())
			continue
		}
		records, err := a.subscriptionCandidates(ctx, sub)
		if err != nil {
			return "", "", len(reasons), err
		}
		prefix := text(sub.Data, "plan")
		if prefix == "" {
			prefix = text(sub.Data, "name")
		}
		if prefix == "" {
			prefix = text(sub.Data, "planId")
		}
		for _, rec := range records {
			node, err := a.realitySubscriptionNode(ctx, rec, sub)
			if err != nil {
				reasons = append(reasons, sub.ID+": "+err.Error())
				continue
			}
			if !compatible(node, format) {
				reasons = append(reasons, sub.ID+": "+incompatibilityReason(node, format))
				continue
			}
			node.Name = prefix + " · " + node.Name
			names[node.Name]++
			if names[node.Name] > 1 {
				node.Name += fmt.Sprintf(" (%d)", names[node.Name])
			}
			nodes = append(nodes, node)
		}
	}

	return a.renderClientNodes(ctx, store.Record{OwnerID: owner, Data: map[string]any{}}, nodes, reasons, format)
}

func (a *App) renderClientNodes(ctx context.Context, sub store.Record, nodes []clientNode, reasons []string, format string) (string, string, int, error) {
	formats := map[string]bool{"clash": true, "singbox": true, "stash": true, "surge": true, "surfboard": true, "loon": true, "qx": true, "egern": true, "v2ray": true, "shadowrocket": true}
	if !formats[format] {
		return "", "", len(reasons), errors.New("未知客户端格式")
	}
	if len(nodes) == 0 {
		return "", "", len(reasons), fmt.Errorf("没有可生成的节点：%s", strings.Join(reasons, "；"))
	}
	var content any
	var output string
	contentType := "text/plain; charset=utf-8"
	switch format {
	case "clash", "stash":
		proxies := []any{}
		names := []string{}
		for _, node := range nodes {
			proxies = append(proxies, clashNode(node))
			names = append(names, node.Name)
		}
		content = map[string]any{"mixed-port": 7890, "mode": "rule", "proxies": proxies, "proxy-groups": []any{map[string]any{"name": "ASWired", "type": "select", "proxies": names}}, "rules": []string{"MATCH,ASWired"}}
		contentType = "application/yaml; charset=utf-8"
	case "singbox":
		outbounds := []any{}
		tags := []string{}
		for _, node := range nodes {
			outbounds = append(outbounds, singboxNode(node))
			tags = append(tags, node.Name)
		}
		outbounds = append([]any{map[string]any{"type": "selector", "tag": "ASWired", "outbounds": tags}}, outbounds...)
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
		content = map[string]any{"inbounds": []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}}, "outbounds": outbounds, "route": map[string]any{"final": "ASWired"}}
		contentType = "application/json; charset=utf-8"
	case "egern":
		proxies := []any{}
		names := []string{}
		for _, node := range nodes {
			proxies = append(proxies, egernNode(node))
			names = append(names, node.Name)
		}
		content = map[string]any{"proxies": proxies, "policy_groups": []any{map[string]any{"select": map[string]any{"name": "ASWired", "policies": names}}}, "rules": []any{map[string]any{"default": "ASWired"}}}
		contentType = "application/yaml; charset=utf-8"
	case "v2ray", "shadowrocket":
		lines := []string{}
		for _, node := range nodes {
			lines = append(lines, nodeURI(node))
		}
		output = base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n"))) + "\n"
	default:
		lines := []string{}
		names := []string{}
		for _, node := range nodes {
			lines = append(lines, iniNode(node, format))
			names = append(names, quoteINI(node.Name))
		}
		if format == "qx" {
			output = "[server_local]\n" + strings.Join(lines, "\n") + "\n[policy]\nstatic=ASWired," + strings.Join(names, ",") + "\n[filter_local]\nfinal,ASWired\n"
		} else {
			output = "[Proxy]\n" + strings.Join(lines, "\n") + "\n[Proxy Group]\nASWired = select, " + strings.Join(names, ", ") + "\n[Rule]\nFINAL,ASWired\n"
		}
	}
	if content != nil {
		modified, e := a.applySubscriptionTemplate(ctx, sub, content, format)
		if e != nil {
			return "", "", len(reasons), e
		}
		content = modified
		blocked, err := a.proxyIPv6Blocked(ctx)
		if err != nil {
			return "", "", len(reasons), err
		}
		if blocked {
			content, err = protectSubscriptionIPv6(content, format)
			if err != nil {
				return "", "", len(reasons), err
			}
		}
		if err := validateSubscriptionOutput(content, format, nodes); err != nil {
			return "", "", len(reasons), err
		}
		var raw []byte
		if format == "singbox" {
			raw, e = json.MarshalIndent(content, "", "  ")
		} else {
			raw, e = marshalConfigYAML(content)
		}
		if e != nil {
			return "", "", len(reasons), e
		}
		output = string(raw)
	} else if format == "surge" || format == "loon" {
		if text(sub.Data, "scriptId") != "" {
			return "", "", len(reasons), errors.New("Surge/Loon文本模板不支持JavaScript覆写")
		}
		template, err := a.selectedTemplate(ctx, sub, format)
		if err != nil {
			return "", "", len(reasons), err
		}
		if template.ID != "" {
			output, err = renderINITemplate(text(template.Data, "content"), nodes, format)
			if err != nil {
				return "", "", len(reasons), err
			}
		}
	} else if text(sub.Data, "scriptId") != "" {
		return "", "", len(reasons), errors.New("此文本客户端格式尚不能应用结构化模板，请移除模板或选择Clash/sing-box/Egern")
	}
	return output, contentType, len(reasons), nil
}

func clashNode(n clientNode) map[string]any {
	p := map[string]any{"name": n.Name, "type": n.Protocol, "server": n.Host, "port": n.Port, "udp": true}
	if n.Protocol == "wireguard" {
		p["private-key"], p["public-key"] = n.PrivateKey, n.PublicKey
		if n.PreSharedKey != "" {
			p["pre-shared-key"] = n.PreSharedKey
		}
		if n.LocalIP != "" {
			p["ip"] = n.LocalIP
		}
		if n.LocalIPv6 != "" {
			p["ipv6"] = n.LocalIPv6
		}
		if n.MTU > 0 {
			p["mtu"] = n.MTU
		}
		if len(n.Reserved) > 0 {
			p["reserved"] = n.Reserved
		}
		return p
	}
	if n.Username != "" {
		p["username"] = n.Username
	}
	if n.Protocol == "anytls" || n.Protocol == "snell" || n.TCPOnly {
		p["udp"] = false
	}
	switch n.Protocol {
	case "snell":
		p["psk"] = n.Password
		p["version"] = n.SnellVersion
	case "vless", "vmess":
		p["uuid"] = n.UUID
	case "ss":
		p["cipher"] = n.Method
		p["password"] = n.Password
	default:
		if n.Password != "" {
			p["password"] = n.Password
		}
	}
	if n.Protocol == "vmess" {
		p["alterId"] = n.AlterID
		p["cipher"] = n.Method
	}
	if n.Flow != "" && n.Protocol == "vless" {
		p["flow"] = n.Flow
	}
	if n.Security != "" && n.Security != "none" {
		p["tls"] = true
		if n.Protocol == "trojan" || n.Protocol == "hysteria" || n.Protocol == "hysteria2" || n.Protocol == "tuic" || n.Protocol == "anytls" {
			p["sni"] = n.SNI
		} else {
			p["servername"] = n.SNI
		}
		p["skip-cert-verify"] = n.Insecure
		if len(n.ALPN) > 0 {
			p["alpn"] = n.ALPN
		}
	}
	if n.Security == "reality" {
		p["client-fingerprint"] = "chrome"
		p["reality-opts"] = map[string]any{"public-key": n.PublicKey, "short-id": n.ShortID}
	}
	if n.Fingerprint != "" {
		p["client-fingerprint"] = n.Fingerprint
	}
	if n.Network != "tcp" {
		p["network"] = n.Network
	}
	if n.Network == "ws" {
		opts := map[string]any{"path": n.Path}
		if n.HostHeader != "" {
			opts["headers"] = map[string]any{"Host": n.HostHeader}
		}
		p["ws-opts"] = opts
	}
	if n.Network == "grpc" {
		p["grpc-opts"] = map[string]any{"grpc-service-name": n.ServiceName}
	}
	if n.Protocol == "tuic" {
		p["uuid"] = n.UUID
		p["reduce-rtt"] = n.ZeroRTT
		if n.Congestion != "" {
			p["congestion-controller"] = n.Congestion
		}
		if n.UDPRelay != "" {
			p["udp-relay-mode"] = n.UDPRelay
		}
	}
	if n.Obfs != "" {
		p["obfs"] = n.Obfs
		if n.Protocol != "hysteria" {
			p["obfs-password"] = n.ObfsPassword
		}
	}
	if n.Protocol == "hysteria" {
		delete(p, "password")
		p["auth-str"], p["up"], p["down"] = n.Password, n.Up, n.Down
	}
	if n.Plugin != "" {
		p["plugin"] = n.Plugin
		p["plugin-opts"] = n.PluginOptions
	}
	return p
}
func singboxNode(n clientNode) map[string]any {
	proto := n.Protocol
	if proto == "ss" {
		proto = "shadowsocks"
	}
	if proto == "socks5" {
		proto = "socks"
	}
	p := map[string]any{"tag": n.Name, "type": proto, "server": n.Host, "server_port": n.Port}
	if n.Username != "" {
		p["username"] = n.Username
	}
	if n.Protocol == "anytls" || n.Protocol == "snell" || n.TCPOnly {
		p["network"] = "tcp"
	}
	switch n.Protocol {
	case "snell":
		p["psk"] = n.Password
		p["version"] = n.SnellVersion
	case "vless", "vmess":
		p["uuid"] = n.UUID
	case "ss":
		p["method"] = n.Method
		p["password"] = n.Password
	default:
		if n.Password != "" {
			p["password"] = n.Password
		}
	}
	if n.Protocol == "vmess" {
		p["security"] = n.Method
		p["alter_id"] = n.AlterID
	}
	if n.Flow != "" && n.Protocol == "vless" {
		p["flow"] = n.Flow
	}
	if n.Security != "" && n.Security != "none" {
		tls := map[string]any{"enabled": true, "server_name": n.SNI, "insecure": n.Insecure}
		if len(n.ALPN) > 0 {
			tls["alpn"] = n.ALPN
		}
		if n.Security == "reality" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			tls["reality"] = map[string]any{"enabled": true, "public_key": n.PublicKey, "short_id": n.ShortID}
		}
		if n.Fingerprint != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": n.Fingerprint}
		}
		p["tls"] = tls
	}
	if n.Network == "ws" {
		tr := map[string]any{"type": "ws", "path": n.Path}
		if n.HostHeader != "" {
			tr["headers"] = map[string]any{"Host": n.HostHeader}
		}
		p["transport"] = tr
	}
	if n.Network == "grpc" {
		p["transport"] = map[string]any{"type": "grpc", "service_name": n.ServiceName}
	}
	if n.Protocol == "tuic" {
		p["uuid"] = n.UUID
		p["zero_rtt_handshake"] = n.ZeroRTT
		if n.Congestion != "" {
			p["congestion_control"] = n.Congestion
		}
		if n.UDPRelay != "" {
			p["udp_relay_mode"] = n.UDPRelay
		}
	}
	if n.Obfs != "" {
		p["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPassword}
		if n.Protocol == "hysteria" {
			p["obfs"] = n.Obfs
		}
	}
	if n.Protocol == "hysteria" {
		delete(p, "password")
		p["auth_str"], p["up_mbps"], p["down_mbps"] = n.Password, n.Up, n.Down
	}
	if n.Plugin != "" {
		plugin := n.Plugin
		if plugin == "obfs" {
			plugin = "obfs-local"
		}
		p["plugin"] = plugin
		p["plugin_opts"] = n.PluginSpec
	}
	return p
}

func configuredExtension(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	default:
		return true
	}
}
func incompatibilityReason(n clientNode, format string) string {
	if n.Plugin != "" {
		return format + "输出尚不能保留Shadowsocks插件 " + n.Plugin
	}
	if n.Obfs != "" {
		return format + "输出尚不能保留HY2混淆 " + n.Obfs
	}
	if len(n.ALPN) > 0 || n.Insecure {
		return format + "输出尚不能保留ALPN/自定义TLS校验参数"
	}
	return format + "不支持此协议、传输或安全组合 (" + n.Protocol + ")"
}

func normalizeSSPlugin(n *clientNode) error {
	if n.Plugin == "obfs-local" {
		n.Plugin = "obfs"
	}
	if n.Plugin != "obfs" && n.Plugin != "v2ray-plugin" {
		return fmt.Errorf("尚未支持Shadowsocks插件 %s 的跨客户端输出", n.Plugin)
	}
	opts := clone(n.PluginOptions)
	if opts == nil {
		opts = map[string]any{}
	}
	for _, part := range strings.Split(n.PluginSpec, ";") {
		if part == "" {
			continue
		}
		key, val, has := strings.Cut(part, "=")
		if n.Plugin == "obfs" {
			if key == "obfs" {
				key = "mode"
			}
			if key == "obfs-host" {
				key = "host"
			}
		}
		if !has {
			opts[key] = true
		} else {
			opts[key] = val
		}
	}
	if n.Plugin == "obfs" {
		for from, to := range map[string]string{"obfs": "mode", "obfs-host": "host"} {
			if value, ok := opts[from]; ok {
				if old, exists := opts[to]; exists && old != value {
					return errors.New("Shadowsocks 插件参数冲突")
				}
				opts[to] = value
				delete(opts, from)
			}
		}
	}
	allowed := map[string]bool{"mode": true, "host": true}
	if n.Plugin == "v2ray-plugin" {
		allowed["path"] = true
		allowed["tls"] = true
		allowed["mux"] = true
	}
	for key, value := range opts {
		if !allowed[key] {
			return fmt.Errorf("Shadowsocks插件参数尚不能保留: %s", key)
		}
		switch value.(type) {
		case string, bool:
		default:
			return errors.New("Shadowsocks插件参数须为文本或布尔值")
		}
		if strings.ContainsAny(fmt.Sprint(value), ";\r\n\x00") {
			return errors.New("Shadowsocks插件参数包含分隔符")
		}
	}
	mode := text(opts, "mode")
	if n.Plugin == "obfs" {
		if mode != "http" && mode != "tls" {
			return errors.New("obfs插件mode须为http或tls")
		}
	} else {
		if mode == "" {
			mode = "websocket"
			opts["mode"] = mode
		}
		if mode != "websocket" {
			return errors.New("v2ray-plugin输出仅支持websocket")
		}
	}
	keys := make([]string, 0, len(opts))
	for key := range opts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, key := range keys {
		value := opts[key]
		if n.Plugin == "v2ray-plugin" && key == "mode" {
			continue
		}
		outKey := key
		if n.Plugin == "obfs" {
			if key == "mode" {
				outKey = "obfs"
			}
			if key == "host" {
				outKey = "obfs-host"
			}
		}
		if key == "tls" || key == "mux" {
			flag := value == true || value == "true"
			opts[key] = flag
			if flag {
				parts = append(parts, outKey)
			}
			continue
		}
		parts = append(parts, outKey+"="+fmt.Sprint(value))
	}
	n.PluginOptions = opts
	n.PluginSpec = strings.Join(parts, ";")
	return nil
}
func egernNode(n clientNode) map[string]any {
	proto := n.Protocol
	if proto == "ss" {
		proto = "shadowsocks"
	}
	p := map[string]any{"name": n.Name, "server": n.Host, "port": n.Port}
	switch n.Protocol {
	case "vless", "vmess":
		p["user_id"] = n.UUID
		if n.Protocol == "vmess" {
			p["security"] = "auto"
		}
	case "ss":
		p["method"] = n.Method
		if n.Method == "chacha20-ietf-poly1305" {
			p["method"] = "chacha20-poly1305"
		}
		p["password"] = n.Password
	default:
		p["password"] = n.Password
	}
	if n.Flow != "" && n.Protocol == "vless" {
		p["flow"] = n.Flow
	}
	if n.Protocol == "vmess" || n.Protocol == "vless" {
		transport := map[string]any{}
		kind := ""
		options := map[string]any{}
		if n.Security != "" && n.Security != "none" {
			kind = "tls"
			options["sni"] = n.SNI
			options["skip_tls_verify"] = false
		}
		if n.Network == "ws" {
			kind = "ws"
			if n.Security != "" && n.Security != "none" {
				kind = "wss"
			}
			options["path"] = n.Path
			if n.HostHeader != "" {
				options["headers"] = map[string]any{"Host": n.HostHeader}
			}
		}
		if n.Security == "reality" {
			options["reality"] = map[string]any{"public_key": n.PublicKey, "short_id": n.ShortID}
		}
		if kind != "" {
			transport[kind] = options
			p["transport"] = transport
		}
		return map[string]any{proto: p}
	}
	if n.Security != "" && n.Security != "none" {
		p["sni"] = n.SNI
		p["skip_tls_verify"] = false
		if n.Protocol == "vmess" || n.Protocol == "vless" {
			p["tls"] = true
		}
	}
	if n.Security == "reality" {
		p["reality"] = map[string]any{"public_key": n.PublicKey, "short_id": n.ShortID}
	}
	if n.Network == "ws" {
		p["websocket"] = map[string]any{"path": n.Path, "host": n.HostHeader}
	}
	return map[string]any{proto: p}
}
func nodeURI(n clientNode) string {
	if n.Protocol == "vmess" {
		path := n.Path
		if n.Network == "grpc" {
			path = n.ServiceName
		}
		obj := map[string]any{"v": "2", "ps": n.Name, "add": n.Host, "port": strconv.Itoa(n.Port), "id": n.UUID, "aid": strconv.Itoa(n.AlterID), "scy": n.Method, "net": n.Network, "type": "none", "host": n.HostHeader, "path": path, "tls": n.Security, "sni": n.SNI, "alpn": strings.Join(n.ALPN, ","), "fp": n.Fingerprint, "allowInsecure": n.Insecure}
		b, _ := json.Marshal(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	}
	u := url.URL{Scheme: n.Protocol, Host: net.JoinHostPort(n.Host, strconv.Itoa(n.Port)), Fragment: n.Name}
	q := url.Values{}
	switch n.Protocol {
	case "vless":
		u.User = url.User(n.UUID)
		q.Set("encryption", "none")
	case "trojan", "hysteria2", "anytls", "snell":
		u.User = url.User(n.Password)
		if n.Protocol == "snell" {
			q.Set("version", strconv.Itoa(n.SnellVersion))
		}
	case "hysteria":
		q.Set("auth", n.Password)
		q.Set("upmbps", strconv.FormatFloat(n.Up, 'f', -1, 64))
		q.Set("downmbps", strconv.FormatFloat(n.Down, 'f', -1, 64))
	case "tuic":
		u.User = url.UserPassword(n.UUID, n.Password)
		if n.Congestion != "" {
			q.Set("congestion_control", n.Congestion)
		}
		if n.UDPRelay != "" {
			q.Set("udp_relay_mode", n.UDPRelay)
		}
		if n.ZeroRTT {
			q.Set("zero_rtt_handshake", "1")
		}
	case "socks5", "http":
		if n.Username != "" || n.Password != "" {
			u.User = url.UserPassword(n.Username, n.Password)
		}
	case "wireguard":
		u.User = url.User(n.PrivateKey)
		q.Set("publickey", n.PublicKey)
		if n.PreSharedKey != "" {
			q.Set("presharedkey", n.PreSharedKey)
		}
		addresses := []string{}
		if n.LocalIP != "" {
			addresses = append(addresses, n.LocalIP)
		}
		if n.LocalIPv6 != "" {
			addresses = append(addresses, n.LocalIPv6)
		}
		q.Set("address", strings.Join(addresses, ","))
		if n.MTU > 0 {
			q.Set("mtu", strconv.Itoa(n.MTU))
		}
		if len(n.Reserved) > 0 {
			parts := []string{}
			for _, v := range n.Reserved {
				parts = append(parts, fmt.Sprint(v))
			}
			q.Set("reserved", strings.Join(parts, ","))
		}
	case "ss":
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(n.Method + ":" + n.Password)))
		if n.Plugin != "" {
			q.Set("plugin", n.Plugin+";"+n.PluginSpec)
		}
	}
	if n.Protocol != "ss" {
		if n.Protocol == "vless" || n.Protocol == "trojan" {
			q.Set("type", n.Network)
		}
		if n.Security != "" {
			q.Set("security", n.Security)
		}
		if n.SNI != "" {
			q.Set("sni", n.SNI)
		}
		if n.Flow != "" {
			q.Set("flow", n.Flow)
		}
		if n.Network == "ws" {
			q.Set("path", n.Path)
			if n.HostHeader != "" {
				q.Set("host", n.HostHeader)
			}
		}
		if n.Network == "grpc" {
			q.Set("serviceName", n.ServiceName)
		}
		if n.Security == "reality" {
			q.Set("pbk", n.PublicKey)
			q.Set("sid", n.ShortID)
			q.Set("fp", "chrome")
		}
	}
	if len(n.ALPN) > 0 {
		q.Set("alpn", strings.Join(n.ALPN, ","))
	}
	if n.Insecure {
		q.Set("insecure", "1")
	}
	if n.Fingerprint != "" {
		q.Set("fp", n.Fingerprint)
	}
	if n.Obfs != "" {
		q.Set("obfs", n.Obfs)
		if n.ObfsPassword != "" {
			q.Set("obfs-password", n.ObfsPassword)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func quoteINI(s string) string {
	if strings.ContainsAny(s, ",=\"#;") {
		return strconv.Quote(s)
	}
	return s
}
func iniNode(n clientNode, format string) string {
	if n.Protocol == "snell" && format == "surge" {
		return quoteINI(n.Name) + " = snell, " + n.Host + ", " + strconv.Itoa(n.Port) + ", psk=" + quoteINI(n.Password) + ", version=" + strconv.Itoa(n.SnellVersion)
	}
	hostport := net.JoinHostPort(n.Host, strconv.Itoa(n.Port))
	name := quoteINI(n.Name)
	if format == "qx" {
		proto := n.Protocol
		if proto == "ss" {
			proto = "shadowsocks"
		}
		parts := []string{proto + "=" + hostport}
		password := n.Password
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			password = n.UUID
			parts = append(parts, "method=none")
		}
		if n.Protocol == "ss" {
			parts = append(parts, "method="+n.Method)
		}
		if password != "" {
			parts = append(parts, "password="+quoteINI(password))
		}
		if n.Security != "" && n.Security != "none" {
			if n.Protocol == "trojan" || n.Protocol == "socks5" || n.Protocol == "http" {
				parts = append(parts, "over-tls=true")
			} else {
				parts = append(parts, "obfs=over-tls")
			}
			parts = append(parts, "obfs-host="+quoteINI(n.SNI), "tls-verification=true")
		}
		if n.Network == "ws" {
			obfs := "ws"
			if n.Security != "" && n.Security != "none" {
				obfs = "wss"
			}
			parts = append(parts, "obfs="+obfs, "obfs-uri="+quoteINI(n.Path))
		}
		if n.Security == "reality" {
			parts = append(parts, "reality-base64-pubkey="+n.PublicKey, "reality-hex-shortid="+n.ShortID)
		}
		parts = append(parts, "tag="+name)
		return strings.Join(parts, ", ")
	}
	proto := n.Protocol
	parts := []string{proto, n.Host, strconv.Itoa(n.Port)}
	if format == "loon" {
		switch n.Protocol {
		case "ss":
			parts[0] = "Shadowsocks"
			parts = append(parts, n.Method, strconv.Quote(n.Password))
		case "vmess":
			parts = append(parts, "auto", strconv.Quote(n.UUID), "alterId=0")
		case "vless":
			parts = append(parts, strconv.Quote(n.UUID))
		default:
			if n.Password != "" {
				parts = append(parts, strconv.Quote(n.Password))
			}
		}
		if n.Network != "tcp" {
			parts = append(parts, "transport="+n.Network, "path="+quoteINI(n.Path))
		}
		if n.Security != "" && n.Security != "none" {
			parts = append(parts, "over-tls=true", "tls-name="+quoteINI(n.SNI), "skip-cert-verify=false")
		}
	} else {
		switch n.Protocol {
		case "ss":
			parts = append(parts, "encrypt-method="+n.Method, "password="+quoteINI(n.Password))
		case "vmess":
			parts = append(parts, "username="+n.UUID, "vmess-aead=true")
		case "trojan":
			parts = append(parts, "password="+quoteINI(n.Password))
		default:
			if n.Password != "" {
				parts = append(parts, quoteINI(n.UUID), quoteINI(n.Password))
			}
		}
		if n.Security != "" && n.Security != "none" {
			parts = append(parts, "tls=true", "sni="+quoteINI(n.SNI), "skip-cert-verify=false")
		}
		if n.Network == "ws" {
			parts = append(parts, "ws=true", "ws-path="+quoteINI(n.Path))
			if n.HostHeader != "" {
				parts = append(parts, "ws-headers="+quoteINI("Host:"+n.HostHeader))
			}
		}
	}
	return name + " = " + strings.Join(parts, ", ")
}

func (a *App) applySubscriptionTemplate(ctx context.Context, sub store.Record, content any, format string) (any, error) {
	configMap, ok := content.(map[string]any)
	if !ok {
		return nil, errors.New("配置根必须是对象")
	}
	rec, selectionErr := a.selectedTemplate(ctx, sub, format)
	if selectionErr != nil {
		return nil, selectionErr
	}
	if rec.ID != "" {
		sub.Data = clone(sub.Data)
		if sub.Data == nil {
			sub.Data = map[string]any{}
		}
		sub.Data["templateId"] = rec.ID
		raw := text(rec.Data, "content")
		if raw == "" {
			raw = text(rec.Data, "config")
		}
		var overlay map[string]any
		if len(raw) > 1<<20 {
			return nil, errors.New("模板过大")
		}
		if err := yaml.Unmarshal([]byte(raw), &overlay); err != nil {
			return nil, fmt.Errorf("模板解析失败: %w", err)
		}
		for key, value := range overlay {
			if key == "proxies" || key == "outbounds" {
				continue
			}
			configMap[key] = value
		}
	}
	var err error
	if format == "clash" || format == "mihomo" || format == "stash" {
		configMap, err = expandTemplate(configMap)
		if err != nil {
			return nil, err
		}
	}
	configMap, err = a.applyRuleOverrides(ctx, sub, configMap, format)
	if err != nil {
		return nil, err
	}
	scriptID := text(sub.Data, "scriptId")
	if scriptID == "" {
		return configMap, nil
	}
	rec, err = a.DB.GetRecord(ctx, "rules", scriptID)
	if err != nil {
		return nil, errors.New("覆写脚本不存在")
	}
	script := text(rec.Data, "script")
	if script == "" {
		script = text(rec.Data, "content")
	}
	if len(script) > 256<<10 {
		return nil, errors.New("脚本过大")
	}
	vm := goja.New()
	vm.SetMaxCallStackSize(256)
	raw, _ := json.Marshal(configMap)
	_ = vm.Set("__aswired_json", string(raw))
	_ = vm.Set("format", format)
	timer := time.AfterFunc(250*time.Millisecond, func() { vm.Interrupt("脚本超过250ms运行限制") })
	defer timer.Stop()
	program := "const config = JSON.parse(__aswired_json);\n" + script + "\n;JSON.stringify(typeof main === 'function' ? main(config) : config)"
	result, err := vm.RunString(program)
	if err != nil {
		return nil, fmt.Errorf("脚本执行失败: %w", err)
	}
	out := result.String()
	if len(out) > 4<<20 {
		return nil, errors.New("覆写结果过大")
	}
	var decoded map[string]any
	if json.Unmarshal([]byte(out), &decoded) != nil || decoded == nil {
		return nil, errors.New("脚本必须返回配置对象")
	}
	return decoded, nil
}
