package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"strings"
)

func auxiliaryProtocol(row map[string]any) bool {
	p := strings.ToLower(text(row, "protocol"))
	return p == "anytls" || p == "snell"
}
func auxiliaryBridgePort(inbound store.Record) int {
	if port := int(number(inbound.Data, "bridgePort")); port > 0 {
		return port
	}
	sum := sha256.Sum256([]byte(inbound.ID))
	return 30000 + int(binary.BigEndian.Uint32(sum[:4])%20000)
}
func (a *App) compileAuxiliaryInbound(ctx context.Context, inbound store.Record) (map[string]any, map[string]any, error) {
	protocol := strings.ToLower(text(inbound.Data, "protocol"))
	port := auxiliaryBridgePort(inbound)
	if port < 1024 || port > 65535 || port == int(number(inbound.Data, "port")) {
		return nil, nil, errors.New("辅助核心本地桥接端口无效，请设置bridgePort")
	}
	others, e := a.DB.ListRecords(ctx, "inbounds", "")
	if e != nil {
		return nil, nil, e
	}
	for _, other := range others {
		if text(other.Data, "serverId") != text(inbound.Data, "serverId") || other.ID == inbound.ID || disabledStatus(other.Data) {
			continue
		}
		if int(number(other.Data, "port")) == port || auxiliaryProtocol(other.Data) && auxiliaryBridgePort(other) == port {
			return nil, nil, errors.New("辅助核心桥接端口冲突，请指定未占用的bridgePort")
		}
	}
	users, e := a.usersForInbound(ctx, inbound)
	if e != nil {
		return nil, nil, e
	}
	if protocol == "snell" && len(users) > 1 {
		return nil, nil, errors.New("当前Snell适配为单凭据监听器，多用户须使用不同入站端口")
	}

	subs, e := a.DB.ListRecords(ctx, "subscriptions", "")
	if e != nil {
		return nil, nil, e
	}
	for _, sub := range subs {
		for _, user := range users {
			if text(user, "email") != text(sub.Data, "credentialEmail")+"."+inbound.ID {
				continue
			}
			member, _ := a.DB.GetRecord(ctx, "members", sub.OwnerID)
			plan, _ := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
			if inheritedLimit(member.Data, plan.Data, text(inbound.Data, "serverId"), "inbound-"+inbound.ID, "ipLimit").Value > 0 {
				return nil, nil, errors.New("AnyTLS/Snell桥接无法验证原客户端IP，请取消该节点IP上限或使用原生Xray协议")
			}
		}
	}
	bridgeUsers := []any{}
	listenerUsers := []any{}
	for _, user := range users {
		uuid := text(user, "id")
		if uuid == "" || text(user, "password") == "" {
			return nil, nil, errors.New("辅助核心用户缺少桥接UUID或协议密码")
		}
		bridgeUsers = append(bridgeUsers, map[string]any{"id": uuid, "email": text(user, "email"), "level": 0})
		listenerUsers = append(listenerUsers, map[string]any{"email": text(user, "email"), "password": text(user, "password"), "bridge": map[string]any{"port": port, "id": uuid}})
	}
	hidden := map[string]any{"tag": "aswired-bridge-" + inbound.ID, "listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"clients": bridgeUsers, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "none"}, "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}}
	listener := map[string]any{"name": text(inbound.Data, "tag"), "type": protocol, "listen": defaultText(inbound.Data, "listen", "0.0.0.0"), "port": number(inbound.Data, "port"), "users": listenerUsers, "udp": false}
	if protocol == "anytls" {
		listener["certificate"] = text(inbound.Data, "certificateFile")
		listener["private_key"] = text(inbound.Data, "keyFile")
		listener["padding_scheme"] = text(inbound.Data, "paddingScheme")
		if text(listener, "certificate") == "" || text(listener, "private_key") == "" {
			return nil, nil, errors.New("AnyTLS需要Agent上已部署的TLS证书及私钥路径")
		}
	} else {
		version := int(number(inbound.Data, "snellVersion"))
		if version == 0 {
			version = 4
		}
		if version != 3 && version != 4 {
			return nil, nil, errors.New("仅启用经过适配的Snell v3/v4")
		}
		listener["version"] = version
	}
	return hidden, listener, nil
}
func (a *App) compileAuxiliary(ctx context.Context, serverID string) (map[string]any, error) {
	return a.compileAuxiliaryExcluding(ctx, serverID, "")
}
func (a *App) compileAuxiliaryExcluding(ctx context.Context, serverID, excluded string) (map[string]any, error) {
	rows, e := a.DB.ListRecords(ctx, "inbounds", "")
	if e != nil {
		return nil, e
	}
	listeners := []any{}
	for _, row := range rows {
		if row.ID == excluded || text(row.Data, "serverId") != serverID || disabledStatus(row.Data) || !auxiliaryProtocol(row.Data) {
			continue
		}
		if err := validateManagedInboundProfile(row.Data); err != nil {
			return nil, err
		}
		_, listener, e := a.compileAuxiliaryInbound(ctx, row)
		if e != nil {
			return nil, e
		}
		listeners = append(listeners, listener)
	}
	return map[string]any{"listeners": listeners}, nil
}
func (a *App) reconcileAuxiliary(ctx context.Context, actor store.User) {
	rows, e := a.DB.ListRecords(ctx, "inbounds", "")
	if e != nil {
		return
	}
	servers := map[string]bool{}
	for _, row := range rows {
		if auxiliaryProtocol(row.Data) {
			servers[text(row.Data, "serverId")] = true
		}
	}
	previous, _ := a.DB.ListRecords(ctx, "_auxiliarySync", "")
	for _, record := range previous {
		servers[record.ID] = true
	}
	for serverID := range servers {
		config, e := a.compileAuxiliary(ctx, serverID)
		old, _ := a.DB.GetRecord(ctx, "_auxiliarySync", serverID)
		if e != nil {
			task, err := a.queue(ctx, actor, serverID, "mihomo.config.apply", map[string]any{"listeners": []any{}})
			if err == nil {
				_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_auxiliarySync", ID: serverID, Version: old.Version, Data: map[string]any{"error": e.Error(), "taskId": task.ID, "status": "blocked"}})
			}
			continue
		}
		raw, _ := json.Marshal(config)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		if text(old.Data, "digest") == digest {
			task, e := a.DB.GetTask(ctx, text(old.Data, "taskId"))
			if e == nil && (task.Status == "queued" || task.Status == "running" || task.Status == "success") {
				continue
			}
		}
		task, e := a.queueCompile(ctx, actor, serverID)
		if e != nil {
			a.audit(ctx, actor, "auxiliary.reconcile.failed", serverID, map[string]any{"error": e.Error()})
			continue
		}
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_auxiliarySync", ID: serverID, Version: old.Version, Data: map[string]any{"digest": digest, "taskId": task.ID, "status": "queued"}})
	}
}
func (a *App) finishAuxiliaryCompile(ctx context.Context, task store.Task) {
	if task.Kind != "core.config.apply" || task.Status != "success" {
		return
	}
	var command agentwire.Command
	if json.Unmarshal(task.Input, &command) != nil {
		return
	}
	aux, ok := command.Params["auxiliary"].(map[string]any)
	if !ok {
		return
	}
	if number(command.Params, "managedProfileVersion") == 2 {
		return
	}
	if nonemptyManagedListeners(aux) {
		return
	}
	actor, e := a.DB.UserByID(ctx, task.ActorID)
	if e != nil {
		actor = store.User{ID: task.ActorID, Role: "admin"}
	}
	next, e := a.queue(ctx, actor, task.ServerID, "mihomo.config.apply", aux)
	if e != nil {
		a.audit(ctx, actor, "auxiliary.dispatch.failed", task.ServerID, map[string]any{"error": fmt.Sprint(e)})
		return
	}
	old, _ := a.DB.GetRecord(ctx, "_auxiliarySync", task.ServerID)
	old.Collection = "_auxiliarySync"
	old.ID = task.ServerID
	if old.Data == nil {
		old.Data = map[string]any{}
	}
	old.Data["taskId"] = next.ID
	old.Data["bridgeTaskId"] = task.ID
	_, _ = a.DB.SaveRecord(ctx, old)
}
