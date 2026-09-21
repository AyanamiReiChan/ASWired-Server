package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"gopkg.in/yaml.v3"
)

type actionInput struct {
	Action     string         `json:"action"`
	TargetID   string         `json:"targetId"`
	Collection string         `json:"collection"`
	Params     map[string]any `json:"params"`
}

func (a *App) action(w http.ResponseWriter, r *http.Request) {
	var in actionInput
	if !decode(w, r, &in) {
		return
	}
	if in.Params == nil {
		in.Params = map[string]any{}
	}
	u := current(r)
	if handled, result, err := a.membershipAction(r.Context(), u, in); handled {
		if err != nil {
			fail(w, 400, "membership_failed", err.Error())
		} else {
			respond(w, 200, result)
		}
		return
	}
	if u.Role != "admin" && in.Action != "subscription.renewal.declare" && in.Action != "token.create" && in.Action != "token.revoke" && !a.memberActionAllowed(r, in) {
		fail(w, 403, "forbidden", "需要管理员权限或资源所有权")
		return
	}
	ctx := r.Context()
	var task store.Task
	var result map[string]any
	var e error
	if handled, result, err := a.operationsAction(ctx, u, in); handled {
		if err != nil {
			fail(w, 400, "operation_failed", err.Error())
		} else {
			respond(w, 200, result)
		}
		return
	}
	if handled, result, err := a.templateAction(ctx, u, in); handled {
		if err != nil {
			fail(w, 400, "template_failed", err.Error())
		} else {
			respond(w, 200, result)
		}
		return
	}
	if u.Role == "admin" {
		if handled, result, err := a.networkAction(ctx, u, in); handled {
			if err != nil {
				fail(w, 400, "network_operation_failed", err.Error())
			} else {
				respond(w, 200, result)
			}
			return
		}
	}
	switch in.Action {
	case "agent.update":
		task, e = a.queueAgentUpdate(ctx, u, in.TargetID, in.Params)
	case "routing.get", "routing.update", "routing.preview":
		result, e = a.routingAction(ctx, u, in)
	case "telegram.webhook.set", "telegram.webhook.delete", "telegram.webhook.status", "telegram.commands.set":
		result, e = a.telegramControl(ctx, u, in.Action)
	case "server.global.update":
		section := text(in.Params, "section")
		if section != "dns" {
			e = errors.New("此操作仅更新 DNS；路由请通过 routing.update 携带 revision 更新")
			break
		}
		value, ok := in.Params["config"].(map[string]any)
		if !ok {
			e = errors.New("配置须为对象")
			break
		}
		var server store.Record
		server, e = a.DB.GetRecord(ctx, "servers", in.TargetID)
		if e != nil {
			break
		}
		global, _ := server.Data["globalConfig"].(map[string]any)
		if global == nil {
			global = map[string]any{}
		}
		global[section] = value
		server.Data["globalConfig"] = global
		_, e = a.DB.SaveRecord(ctx, server)
		if e == nil && boolean(in.Params, "apply") {
			task, e = a.queueCompile(ctx, u, server.ID)
		} else {
			result = map[string]any{"success": e == nil}
		}
	case "server.config.apply":
		task, e = a.queueCompile(ctx, u, in.TargetID)
	case "inbound.config.apply", "outbound.config.apply":
		c := "inbounds"
		if strings.HasPrefix(in.Action, "outbound") {
			c = "outbounds"
		}
		var rec store.Record
		rec, e = a.DB.GetRecord(ctx, c, in.TargetID)
		if e == nil {
			task, e = a.queueCompile(ctx, u, text(rec.Data, "serverId"))
		}
	case "routing.apply":
		id := in.TargetID
		if in.Collection == "policies" {
			if p, err := a.DB.GetRecord(ctx, "policies", id); err == nil {
				id = text(p.Data, "serverId")
			}
		}
		if id == "" {
			e = errors.New("请选择目标服务器")
		} else {
			task, e = a.queueCompile(ctx, u, id)
		}
	case "mihomo.config.apply", "mihomo.users.sync", "mihomo.status", "mihomo.start", "mihomo.stop", "mihomo.restart", "mihomo.config.get", "core.status", "core.config.get", "core.config.apply", "core.config.history", "core.config.restore", "core.start", "core.stop", "core.restart", "core.stats", "core.users.sync", "core.policy.apply", "core.connections", "server.scan", "server.ports.check", "certificate.deploy", "site.apply", "network.latency":
		task, e = a.queue(ctx, u, in.TargetID, in.Action, in.Params)
	case "traffic.reconcile":
		servers, err := a.DB.ListRecords(ctx, "servers", "")
		if err != nil {
			e = err
			break
		}
		items := []any{}
		for _, server := range servers {
			if disabledStatus(server.Data) {
				continue
			}
			queued, err := a.queue(ctx, u, server.ID, "core.stats", map[string]any{})
			if err != nil {
				items = append(items, map[string]any{"serverId": server.ID, "error": err.Error()})
			} else {
				items = append(items, taskRow(queued))
			}
		}
		result = map[string]any{"tasks": items, "message": "已请求实际核心计数，收到结果后按原始样本入账；重复样本不会重计。"}
	case "member.credentials.sync":
		a.reconcileUsers(ctx, u)
		result = map[string]any{"success": true, "message": "已根据有效套餐建立同步任务，请查看节点执行结果"}
	case "task.retry":
		original, err := a.DB.GetTask(ctx, in.TargetID)
		if err != nil {
			e = err
			break
		}
		if original.LogsDeleted {
			e = errors.New("任务日志已清理，不能重试；请根据当前配置重新执行")
			break
		}
		if original.Status == "superseded" {
			e = errors.New("任务已失效，请根据当前配置重新发布")
			break
		}
		if original.Status == "queued" || original.Status == "running" {
			e = errors.New("任务仍在执行，请先等待或核对结果")
			break
		}
		if err = a.validateManagedInboundTask(ctx, original); err != nil {
			e = err
			break
		}
		var cmd agentwire.Command
		if err = json.Unmarshal(original.Input, &cmd); err != nil {
			e = err
			break
		}
		if cmd.Action == "agent.update" {
			task, e = a.queueAgentUpdate(ctx, u, original.ServerID, cmd.Params)
		} else {
			task, e = a.queue(ctx, u, original.ServerID, cmd.Action, cmd.Params)
		}
	case "node.health.check":
		result, e = a.nodeHealth(ctx, in.TargetID)
	case "source.sync":
		result, e = a.syncSource(ctx, in.TargetID)
	case "subscription.renewal.declare":
		sub, err := a.DB.GetRecord(ctx, "subscriptions", in.TargetID)
		if err != nil {
			e = err
			break
		}
		if u.Role != "admin" && sub.OwnerID != u.ID {
			fail(w, 403, "forbidden", "不能操作他人的套餐")
			return
		}
		_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_renewalDeclarations", ID: newID(), OwnerID: sub.OwnerID, Data: map[string]any{"subscriptionId": sub.ID, "declaredAt": time.Now().UTC(), "status": "待核对"}})
		result = map[string]any{"success": true, "message": "续费声明已提交，套餐期限未自动改变"}
	case "server.credentials.rotate":
		cred, err := a.DB.GetRecord(ctx, "_agentCredentials", in.TargetID)
		if err != nil {
			e = err
			break
		}
		cred.Data = map[string]any{"serverToken": newID() + newID(), "agentToken": newID() + newID()}
		_, e = a.DB.SaveRecord(ctx, cred)
		result = map[string]any{"success": e == nil, "message": "凭据已重置，请更新节点配置后重新连接"}
	case "backup.create":
		result, e = a.createBackup(ctx, u)
	case "backup.remote.upload", "backup.remote.download", "backup.remote.test", "backup.remote.prune":
		result, e = a.remoteBackup(ctx, u, in.Action, in.Params)
	case "speedtest.run":
		task, e = a.queueHome(ctx, u, in.TargetID, in.Params)
	case "federation.publish", "federation.revoke", "federation.connect", "federation.sync", "federation.disconnect", "federation.agent.publish", "federation.agent.revoke", "federation.agent.connect", "federation.agent.execute", "federation.agent.result":
		result, e = a.federationAction(ctx, u, in)
	case "token.create":
		result, e = a.createAPIToken(ctx, u, in.Params)
	case "token.revoke":
		rec, err := a.DB.GetRecord(ctx, "_apiTokens", in.TargetID)
		if err != nil {
			e = err
			break
		}
		if u.Role != "admin" && rec.OwnerID != u.ID {
			fail(w, 403, "forbidden", "无权撤销该令牌")
			return
		}
		e = a.DB.DeleteRecord(ctx, "_apiTokens", in.TargetID)
		_ = a.DB.DeleteRecord(ctx, "tokens", in.TargetID)
		result = map[string]any{"success": e == nil}
	case "notification.test", "notification.channel.test", "telegram.test":
		result, e = a.notificationTest(ctx, u, in.TargetID, in.Params)
	case "komari.test", "komari.sync":
		result, e = a.syncKomari(ctx, in.Action == "komari.sync")
	case "system.update":
		result, e = a.checkRelease(ctx, text(in.Params, "channel") == "prerelease")
	default:
		fail(w, 501, "not_implemented", "该执行能力尚未接通，配置可保存，但不会模拟成功")
		return
	}
	if e != nil {
		fail(w, 400, "action_failed", e.Error())
		return
	}
	if task.ID != "" {
		if u.Role != "admin" {
			respond(w, 202, map[string]any{"success": true, "accepted": true, "message": "操作已受理，完成后会更新资源状态"})
			return
		}
		respond(w, 202, map[string]any{"task": taskRow(task)})
		return
	}
	a.audit(ctx, u, in.Action, in.TargetID, nil)
	respond(w, 200, result)
}

var errUDPNodeTest = errors.New("该节点使用 UDP，请在节点测速中执行代理延迟测试")

func nodeTestAddress(row map[string]any) (string, error) {
	node := row
	if raw := text(row, "uri"); raw != "" {
		parsed, err := parseImportedURI(raw)
		if err != nil {
			return "", errors.New("节点链接无效，无法测试")
		}
		node = parsed
	}
	switch strings.ToLower(defaultText(node, "protocol", text(node, "type"))) {
	case "hysteria", "hysteria2", "hy2", "tuic", "wireguard", "wg":
		return "", errUDPNodeTest
	}
	host := strings.TrimSpace(text(node, "host"))
	port := number(node, "port")
	if host == "" || strings.ContainsAny(host, "/?#@ \t\r\n") || port < 1 || port > 65535 || port != float64(int(port)) {
		return "", errors.New("节点缺少可测试的地址和端口")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func preserveNodeLatency(row, previous map[string]any) {
	fields := []string{"latency", "latencyKind", "latencyStatus", "latencyError", "testedAt"}
	for _, field := range fields {
		delete(row, field)
	}
	address, err := nodeTestAddress(row)
	oldAddress, oldErr := nodeTestAddress(previous)
	if err != nil || oldErr != nil || address != oldAddress {
		return
	}
	for _, field := range fields {
		if value, exists := previous[field]; exists {
			row[field] = value
		}
	}
}

func (a *App) nodeHealth(ctx context.Context, id string) (map[string]any, error) {
	rec, err := a.DB.GetRecord(ctx, "nodes", id)
	if err != nil {
		return nil, err
	}
	actor, hasActor := ctx.Value(userKey{}).(store.User)
	memberTest := hasActor && actor.Role != "admin"
	address, testErr := nodeTestAddress(rec.Data)
	if errors.Is(testErr, errUDPNodeTest) {
		return nil, testErr
	}
	if testErr == nil {
		address, testErr = a.relayEntry(ctx, rec.ID, address)
	}
	started := time.Now()
	if testErr == nil {
		testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		dial := (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		if rec.OwnerID != "" || memberTest {
			dial = publicDial
		}
		var conn net.Conn
		conn, testErr = dial(testCtx, "tcp", address)
		if testErr == nil {
			conn.Close()
		} else if errors.Is(testCtx.Err(), context.DeadlineExceeded) {
			testErr = errors.New("TCP连接超时")
		} else {
			testErr = fmt.Errorf("TCP连接失败: %w", testErr)
		}
	}
	rec.Data["latencyKind"] = "tcp"
	rec.Data["testedAt"] = time.Now().UTC()
	delete(rec.Data, "latency")
	delete(rec.Data, "latencyError")
	if testErr != nil {
		rec.Data["latencyStatus"] = "failed"
		rec.Data["latencyError"] = testErr.Error()
		if !memberTest && !disabledStatus(rec.Data) && !boolean(rec.Data, "managedInbound") {
			rec.Data["status"] = "不可达"
		}
	} else {
		rec.Data["latency"] = float64(time.Since(started).Microseconds()) / 1000
		rec.Data["latencyStatus"] = "success"
		if !memberTest && !disabledStatus(rec.Data) && !boolean(rec.Data, "managedInbound") {
			rec.Data["status"] = "可达"
		}
	}
	if _, err := a.DB.SaveRecord(ctx, rec); err != nil {
		return nil, fmt.Errorf("保存测速结果失败: %w", err)
	}
	if testErr != nil {
		if memberTest {
			return nil, errors.New("节点测速失败，请稍后重试或联系管理员")
		}
		return nil, testErr
	}
	return map[string]any{"latency": rec.Data["latency"], "kind": "tcp", "proxyVerified": false}, nil
}
func (a *App) syncSource(ctx context.Context, id string) (map[string]any, error) {
	source, e := a.DB.GetRecord(ctx, "sources", id)
	if e != nil {
		return nil, e
	}
	u, e := url.Parse(text(source.Data, "url"))
	if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, errors.New("订阅地址须为HTTP(S)链接")
	}
	var include, exclude *regexp.Regexp
	if s := text(source.Data, "include"); s != "" {
		include, e = regexp.Compile(s)
		if e != nil {
			return nil, errors.New("保留名称匹配表达式无效")
		}
	}
	if s := text(source.Data, "exclude"); s != "" {
		exclude, e = regexp.Compile(s)
		if e != nil {
			return nil, errors.New("排除名称匹配表达式无效")
		}
	}
	raw, userinfo, provenance, e := a.fetchSource(ctx, source)
	if e != nil {
		return nil, e
	}
	nodes := []map[string]any{}
	parseSkipped := 0
	var clash struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(raw, &clash) == nil && len(clash.Proxies) > 0 {
		for _, proxy := range clash.Proxies {
			node := clone(proxy)
			node["host"] = text(proxy, "server")
			node["protocol"] = strings.ToUpper(text(proxy, "type"))
			nodes = append(nodes, node)
		}
	} else {
		body := strings.TrimSpace(string(raw))
		if !strings.Contains(body, "://") {
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if decoded, err := encoding.DecodeString(body); err == nil {
					body = string(decoded)
					break
				}
			}
		}
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if parsed, err := parseImportedURI(strings.TrimSpace(line)); err == nil {
				nodes = append(nodes, parsed)
			} else {
				parseSkipped++
			}
		}
	}
	if len(nodes) == 0 {
		return map[string]any{"success": false, "nodes": 0, "updated": 0, "skipped": parseSkipped}, fmt.Errorf("订阅未包含可识别的节点，保留上次数据（跳过%d个）", parseSkipped)
	}
	if len(nodes) > 10000 {
		return nil, errors.New("订阅节点超过10000个，保留上次数据")
	}
	existing, e := a.DB.ListRecords(ctx, "nodes", "")
	if e != nil {
		return nil, e
	}
	byID := map[string]store.Record{}
	for _, record := range existing {
		byID[record.ID] = record
	}
	mode := defaultText(source.Data, "syncMode", "merge")
	if mode != "merge" && mode != "update-only" && mode != "add-only" {
		return nil, errors.New("同步方式无效")
	}
	matchBy := defaultText(source.Data, "matchBy", "name-address")
	if matchBy != "name-address" && matchBy != "name" && matchBy != "address" && matchBy != "identity" {
		return nil, errors.New("节点匹配方式无效")
	}
	updated := 0
	skipped := parseSkipped
	reasons := []string{}
	if parseSkipped > 0 {
		reasons = append(reasons, fmt.Sprintf("%d个节点链接无法解析", parseSkipped))
	}
	seenNodes := map[string]bool{}
	changes := []store.Record{}
	for _, node := range nodes {
		normalized, err := normalizedProxyNode(node, true)
		if err != nil {
			skipped++
			reasons = append(reasons, text(node, "name")+": "+err.Error())
			continue
		}
		node = normalized
		originalName := text(node, "name")
		name := originalName
		if include != nil && !include.MatchString(name) {
			continue
		}
		if exclude != nil && exclude.MatchString(name) {
			continue
		}
		key := fmt.Sprintf("%s|%v|%v|%v|%v", id, node["protocol"], node["host"], node["port"], originalName)
		switch matchBy {
		case "name":
			key = id + "|name|" + originalName
		case "address":
			key = fmt.Sprintf("%s|address|%v|%v|%v", id, node["protocol"], node["host"], node["port"])
		case "identity":
			key = id + "|identity|" + nodeImportIdentity(node)
		}
		hash := sha256.Sum256([]byte(key))
		nodeID := "src-" + hex.EncodeToString(hash[:12])
		if seenNodes[nodeID] {
			continue
		}
		seenNodes[nodeID] = true
		old := byID[nodeID]
		if old.ID != "" && (old.OwnerID != source.OwnerID || text(old.Data, "sourceId") != id) {
			return nil, errors.New("订阅节点归属发生冲突")
		}
		if mode == "update-only" && old.ID == "" || mode == "add-only" && old.ID != "" {
			continue
		}
		if old.ID != "" && text(old.Data, "name") != text(old.Data, "importedName") {
			name = text(old.Data, "name")
		} else {
			name = text(source.Data, "prefix") + name
		}
		node["importedName"] = text(source.Data, "prefix") + originalName
		node["name"] = name
		node["sourceId"] = id
		node["source"] = text(source.Data, "name")
		node["status"] = "待测试"
		node["sourceMissing"] = false
		for _, field := range []string{"tags", "region", "weight", "visible", "description"} {
			if v, ok := old.Data[field]; ok {
				node[field] = v
			}
		}
		preserveNodeLatency(node, old.Data)
		if disabledStatus(old.Data) {
			node["status"] = old.Data["status"]
			if boolean(old.Data, "disabled") {
				node["disabled"] = true
			}
		} else {
			switch text(node, "latencyStatus") {
			case "success":
				node["status"] = "可达"
			case "failed":
				node["status"] = "不可达"
			}
		}
		changes = append(changes, store.Record{Collection: "nodes", ID: nodeID, OwnerID: source.OwnerID, Data: node, Version: old.Version})
		updated++
	}
	if skipped == len(nodes)+parseSkipped {
		return map[string]any{"success": false, "nodes": 0, "updated": 0, "skipped": skipped, "reasons": reasons}, fmt.Errorf("订阅未包含有效的受支持节点，保留上次数据（跳过%d个）", skipped)
	}
	if mode != "add-only" {
		for _, previous := range existing {
			if _, err := normalizedProxyNode(previous.Data, true); err != nil {
				continue
			}
			if text(previous.Data, "sourceId") == id && !seenNodes[previous.ID] {
				previous.Data["status"] = "禁用"
				previous.Data["sourceMissing"] = true
				changes = append(changes, previous)
			}
		}
	}
	source.Data["nodes"] = len(seenNodes)
	source.Data["updated"] = time.Now().UTC().Format(time.RFC3339)
	source.Data["status"] = "正常"
	source.Data["subscriptionUserInfo"] = userinfo
	source.Data["fetchProvenance"] = provenance
	changes = append(changes, source)
	if source.OwnerID != "" {
		_, e = a.DB.CompareAndSaveOwnedResources(ctx, source.OwnerID, a.memberQuotas(ctx, source.OwnerID), changes)
	} else {
		_, e = a.DB.CompareAndSaveRecords(ctx, changes)
	}
	return map[string]any{"success": e == nil, "nodes": len(seenNodes), "updated": updated, "skipped": skipped, "reasons": reasons, "syncMode": mode, "matchBy": matchBy}, e
}
func parseImportedURI(raw string) (map[string]any, error) {
	if strings.HasPrefix(raw, "ss://") {
		return parseShadowsocksURI(raw)
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme == "" {
		return nil, errors.New("invalid node URI")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "vmess" {
		b, e := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(raw, "vmess://"), "="))
		if e != nil {
			return nil, e
		}
		var p map[string]any
		if e = json.Unmarshal(b, &p); e != nil {
			return nil, e
		}
		port, _ := strconv.Atoi(fmt.Sprint(p["port"]))
		node := map[string]any{"name": p["ps"], "protocol": "VMess", "host": p["add"], "port": port, "uuid": p["id"], "network": p["net"], "sni": p["sni"], "security": p["tls"], "path": p["path"], "hostHeader": p["host"], "method": p["scy"], "alterId": p["aid"], "fingerprint": p["fp"], "alpn": p["alpn"], "uri": raw}
		if text(p, "net") == "grpc" {
			node["serviceName"] = p["path"]
		}
		if text(p, "type") != "" && text(p, "type") != "none" {
			return nil, errors.New("暂不支持 VMess 伪装类型")
		}
		if boolean(p, "allowInsecure") || text(p, "allowInsecure") == "1" {
			node["skipCertVerify"] = true
		}
		return node, nil
	}
	switch scheme {
	case "vless", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic", "socks", "socks5", "http", "https", "anytls", "snell", "wireguard", "wg":
	default:
		return nil, errors.New("unsupported node URI")
	}
	portText := u.Port()
	if portText == "" {
		switch scheme {
		case "hysteria2", "hy2", "anytls", "https":
			portText = "443"
		case "http":
			portText = "80"
		}
	}
	port, e := strconv.Atoi(portText)
	if e != nil || port < 1 || port > 65535 || u.Hostname() == "" {
		return nil, errors.New("invalid node address")
	}
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	node := map[string]any{"name": name, "protocol": strings.ToUpper(scheme), "host": u.Hostname(), "port": port, "uri": raw}
	q, queryErr := url.ParseQuery(u.RawQuery)
	if queryErr != nil {
		return nil, errors.New("invalid node URI query")
	}
	allowedQuery := map[string]bool{}
	for _, key := range []string{"security", "sni", "peer", "type", "path", "host", "pbk", "sid", "flow", "fp", "serviceName", "obfs", "obfs-password", "congestion_control", "udp_relay_mode", "version", "auth", "upmbps", "downmbps", "publickey", "presharedkey", "address", "mtu", "reserved", "zero_rtt_handshake", "reduce-rtt", "insecure", "allowInsecure", "alpn", "encryption", "protocol"} {
		allowedQuery[key] = true
	}
	for key := range q {
		if !allowedQuery[key] {
			return nil, fmt.Errorf("暂不支持节点链接参数 %s", key)
		}
	}
	for key, values := range q {
		if len(values) > 1 {
			return nil, fmt.Errorf("节点链接包含重复参数 %s", key)
		}
	}
	if scheme == "vless" {
		for _, key := range []string{"type", "security", "pbk", "sni", "peer", "sid", "flow", "encryption"} {
			if len(q[key]) > 1 {
				return nil, errors.New("VLESS URI包含重复配置字段")
			}
		}
		if q.Get("encryption") != "" && q.Get("encryption") != "none" || q.Get("peer") != "" && q.Get("sni") != "" && q.Get("peer") != q.Get("sni") {
			return nil, errors.New("VLESS URI配置字段无效或不一致")
		}
		for _, key := range []string{"plugin", "obfs", "obfs-password", "congestion_control", "udp_relay_mode"} {
			if q.Get(key) != "" {
				return nil, errors.New("VLESS URI包含其他协议专用扩展")
			}
		}
		if u.User != nil {
			if _, exists := u.User.Password(); exists {
				return nil, errors.New("VLESS URI仅接受 UUID 用户信息")
			}
		}
	}
	for from, to := range map[string]string{"security": "security", "sni": "sni", "peer": "sni", "type": "network", "path": "path", "host": "hostHeader", "pbk": "publicKey", "sid": "shortId", "flow": "flow", "fp": "fingerprint", "serviceName": "serviceName", "obfs": "obfs", "obfs-password": "obfsPassword", "congestion_control": "congestionController", "udp_relay_mode": "udpRelayMode", "version": "snellVersion", "auth": "password", "upmbps": "up", "downmbps": "down", "publickey": "publicKey", "presharedkey": "preSharedKey", "address": "ip", "mtu": "mtu"} {
		if q.Get(from) != "" {
			node[to] = q.Get(from)
		}
	}
	if u.User != nil {
		if scheme == "vless" || scheme == "tuic" {
			node["uuid"] = u.User.Username()
		} else {
			node["password"] = u.User.Username()
		}
		if pass, ok := u.User.Password(); ok {
			node["password"] = pass
			node["username"] = u.User.Username()
		}
	}
	if scheme == "hy2" || scheme == "hysteria2" {
		node["protocol"] = "Hysteria2"
		node["security"] = "tls"
		if u.User != nil {
			if pass, ok := u.User.Password(); ok {
				node["password"] = u.User.Username() + ":" + pass
				delete(node, "username")
			}
		}
	}
	if scheme == "tuic" {
		node["security"] = "tls"
	}
	if scheme == "trojan" || scheme == "anytls" || scheme == "hysteria" {
		node["security"] = "tls"
	}
	if scheme == "hysteria" && q.Get("protocol") != "" && q.Get("protocol") != "udp" {
		return nil, errors.New("Hysteria 仅支持 UDP 传输")
	}
	if scheme == "http" || scheme == "https" {
		node["protocol"] = "HTTP"
		if scheme == "https" {
			node["security"] = "tls"
		}
	}
	if scheme == "wireguard" || scheme == "wg" {
		node["protocol"] = "WireGuard"
		if u.User != nil {
			node["privateKey"] = u.User.Username()
		}
		delete(node, "password")
		if address := q.Get("address"); address != "" {
			delete(node, "ip")
			for _, ip := range strings.Split(address, ",") {
				if strings.Contains(ip, ":") {
					node["ipv6"] = ip
				} else {
					node["ip"] = ip
				}
			}
		}
		if value := q.Get("reserved"); value != "" {
			values := []any{}
			for _, part := range strings.Split(value, ",") {
				n, err := strconv.Atoi(part)
				if err != nil {
					return nil, errors.New("WireGuard reserved 无效")
				}
				values = append(values, n)
			}
			node["reserved"] = values
		}
	}
	if q.Get("zero_rtt_handshake") == "1" || q.Get("reduce-rtt") == "true" {
		node["zero_rtt_handshake"] = true
	}
	if scheme == "socks" || scheme == "socks5" {
		node["protocol"] = "SOCKS5"
		if u.User != nil {
			node["username"] = u.User.Username()
			if _, ok := u.User.Password(); !ok {
				node["password"] = ""
			}
		}
	}
	if q.Get("insecure") == "1" || q.Get("insecure") == "true" || q.Get("allowInsecure") == "1" {
		node["skipCertVerify"] = true
	}
	if q.Get("alpn") != "" {
		node["alpn"] = strings.Split(q.Get("alpn"), ",")
	}
	return node, nil
}
func decodeSubscriptionBase64(value string) (string, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if raw, e := encoding.DecodeString(value); e == nil {
			return string(raw), nil
		}
	}
	return "", errors.New("invalid base64 credential")
}
func parseShadowsocksURI(raw string) (map[string]any, error) {
	body := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if index := strings.Index(body, "#"); index >= 0 {
		fragment = body[index:]
		body = body[:index]
	}
	if !strings.Contains(body, "@") {
		decoded, e := decodeSubscriptionBase64(body)
		if e != nil {
			return nil, e
		}
		body = decoded
	}
	u, e := url.Parse("ss://" + body + fragment)
	if e != nil || u.User == nil {
		return nil, errors.New("invalid Shadowsocks URI")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 || u.Hostname() == "" {
		return nil, errors.New("invalid Shadowsocks address")
	}
	method, password := u.User.Username(), ""
	if pass, ok := u.User.Password(); ok {
		password = pass
	} else {
		decoded, e := decodeSubscriptionBase64(method)
		if e != nil {
			return nil, e
		}
		parts := strings.SplitN(decoded, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid Shadowsocks credential")
		}
		method, password = parts[0], parts[1]
	}
	if method == "" || password == "" {
		return nil, errors.New("empty Shadowsocks credential")
	}
	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	node := map[string]any{"name": name, "protocol": "Shadowsocks", "host": u.Hostname(), "port": port, "method": method, "cipher": method, "password": password, "uri": raw}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid Shadowsocks URI query")
	}
	for key, values := range query {
		if key != "plugin" || len(values) > 1 {
			return nil, fmt.Errorf("不支持或重复的 Shadowsocks 参数 %s", key)
		}
	}
	if plugin := query.Get("plugin"); plugin != "" {
		parts := strings.Split(plugin, ";")
		node["plugin"] = parts[0]
		options := map[string]any{}
		for _, option := range parts[1:] {
			key, value, found := strings.Cut(option, "=")
			if found {
				options[key] = value
			} else {
				options[key] = true
			}
		}
		node["plugin-opts"] = options
	}
	return node, nil
}
