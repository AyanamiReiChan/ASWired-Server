package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
)

func (a *App) compile(ctx context.Context, serverID string) (map[string]any, error) {
	server, e := a.DB.GetRecord(ctx, "servers", serverID)
	if e != nil {
		return nil, e
	}
	return a.compileServer(ctx, server)
}

func (a *App) compileServer(ctx context.Context, server store.Record) (map[string]any, error) {
	return a.compileServerDraft(ctx, server, true)
}

func (a *App) compileServerDraft(ctx context.Context, server store.Record, validate bool) (map[string]any, error) {
	return a.compileServerExcluding(ctx, server, validate, "")
}

func (a *App) compileServerExcluding(ctx context.Context, server store.Record, validate bool, excludedInbound string) (map[string]any, error) {
	serverID := server.ID
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "stats": map[string]any{}, "policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}, "system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true, "statsOutboundUplink": true, "statsOutboundDownlink": true}}, "inbounds": []any{}, "outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}}
	if global, ok := server.Data["globalConfig"].(map[string]any); ok {
		for k, v := range global {
			if k != "inbounds" && k != "outbounds" {
				cfg[k] = v
			}
		}
	}
	ins, e := a.DB.ListRecords(ctx, "inbounds", "")
	if e != nil {
		return nil, e
	}
	inbounds := []any{}
	for _, rec := range ins {
		if rec.ID == excludedInbound {
			continue
		}
		r := rec.Data
		if text(r, "serverId") != serverID || disabledStatus(r) {
			continue
		}
		if err := validateManagedInboundProfile(r); err != nil {
			return nil, fmt.Errorf("%s: %w", text(r, "name"), err)
		}
		if auxiliaryProtocol(r) {
			bridge, _, err := a.compileAuxiliaryInbound(ctx, rec)
			if err != nil {
				return nil, err
			}
			inbounds = append(inbounds, bridge)
			continue
		}
		users, e := a.usersForInbound(ctx, rec)
		if e != nil {
			return nil, e
		}
		inbound, e := compileInbound(r, users)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", text(r, "name"), e)
		}
		inbounds = append(inbounds, inbound)
	}
	cfg["inbounds"] = inbounds
	outs, e := a.DB.ListRecords(ctx, "outbounds", "")
	if e != nil {
		return nil, e
	}
	outbounds := cfg["outbounds"].([]any)
	for _, rec := range outs {
		if text(rec.Data, "serverId") != serverID || disabledStatus(rec.Data) {
			continue
		}
		out, e := compileOutbound(rec.Data)
		if e != nil {
			return nil, e
		}
		outbounds = append(outbounds, out)
	}
	cfg["outbounds"] = outbounds
	policies, e := a.DB.ListRecords(ctx, "policies", "")
	if e != nil {
		return nil, e
	}
	for _, p := range policies {
		if text(p.Data, "serverId") == serverID {
			if routing, ok := p.Data["routing"].(map[string]any); ok {
				if global, _ := server.Data["globalConfig"].(map[string]any); global["routing"] == nil {
					cfg["routing"] = routing
				}
			}
			if dns, ok := p.Data["dns"].(map[string]any); ok {
				if global, _ := server.Data["globalConfig"].(map[string]any); global["dns"] == nil {
					cfg["dns"] = dns
				}
			}
		}
	}
	// Global settings and stored policy rows contain nested maps. Work on a
	// detached tree before routing normalization changes rule ordering.
	cfg, e = cloneProxyConfig(cfg)
	if e != nil {
		return nil, e
	}
	if err := prepareRouting(cfg, text(server.Data, "routingDefaultOutbound")); err != nil && validate {
		return nil, err
	}
	blocked, err := a.proxyIPv6Blocked(ctx)
	if err != nil {
		return nil, err
	}
	return applyProxyNetworkDefaults(cfg, blocked)
}
func compileInbound(r map[string]any, users []map[string]any) (map[string]any, error) {
	if err := validateManagedInboundProfile(r); err != nil {
		return nil, err
	}
	clients := []any{}
	for _, user := range users {
		entry := clone(user)
		for _, key := range []string{"inbound", "protocol", "speed", "connectionLimit", "ipLimit"} {
			delete(entry, key)
		}
		clients = append(clients, entry)
	}
	_, security := inboundTransport(r)
	if security != "reality" {
		return compileProtocolInbound(r, clients)
	}
	target := defaultText(r, "target", text(r, "realityTarget"))
	if target == "" {
		return nil, errors.New("REALITY 缺少 Target")
	}
	names := stringList(r["sni"])
	if len(names) == 0 {
		names = stringList(r["serverNames"])
	}
	if len(names) == 0 {
		return nil, errors.New("REALITY 缺少 SNI")
	}
	reality := map[string]any{"target": target, "serverNames": names, "privateKey": text(r, "privateKey"), "shortIds": stringList(r["shortIds"]), "xver": number(r, "xver"), "show": boolean(r, "show")}
	if boolean(r, "allowEmptyShortId") {
		reality["shortIds"] = append(stringList(r["shortIds"]), "")
	}
	for _, key := range []string{"minClientVer", "maxClientVer", "maxTimeDiff"} {
		if value, ok := r[key]; ok && value != "" {
			reality[key] = value
		}
	}
	stream := map[string]any{"network": "tcp", "security": "reality", "realitySettings": reality}
	if custom, ok := r["streamSettings"].(map[string]any); ok {
		if sockopt, ok := custom["sockopt"]; ok {
			stream["sockopt"] = sockopt
		}
	}
	inbound := map[string]any{"tag": text(r, "tag"), "listen": defaultText(r, "listen", "0.0.0.0"), "port": number(r, "port"), "protocol": "vless", "settings": map[string]any{"clients": clients, "decryption": "none"}, "streamSettings": stream}
	if text(r, "sniffing") != "关闭" {
		inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": text(r, "sniffing") == "仅路由"}
	}
	return inbound, nil
}

func defaultText(m map[string]any, k, def string) string {
	if s := text(m, k); s != "" {
		return s
	}
	return def
}
func compileOutbound(r map[string]any) (map[string]any, error) {
	if err := validateRealityOutbound(r); err != nil {
		return nil, err
	}
	p := strings.ToLower(text(r, "protocol"))
	out := map[string]any{"tag": text(r, "tag"), "protocol": p}
	if settings, ok := r["settings"].(map[string]any); ok {
		out["settings"] = settings
	} else if p == "freedom" || p == "blackhole" {
		out["settings"] = map[string]any{}
	} else {
		return nil, errors.New("代理出站需要完整settings配置，目标地址不足以包含鉴权信息")
	}
	if stream, ok := r["streamSettings"].(map[string]any); ok {
		out["streamSettings"] = stream
	}
	return out, nil
}
func (a *App) queueCompile(ctx context.Context, u store.User, serverID string) (store.Task, error) {
	if err := a.checkInboundCapabilities(ctx, serverID); err != nil {
		return store.Task{}, err
	}
	cfg, e := a.compile(ctx, serverID)
	if e != nil {
		return store.Task{}, e
	}
	aux, e := a.compileAuxiliary(ctx, serverID)
	if e != nil {
		return store.Task{}, e
	}
	params := map[string]any{"config": cfg, "managedInbounds": true, "managedProfileVersion": 2}
	listeners, _ := aux["listeners"].([]any)
	old, _ := a.DB.GetRecord(ctx, "_auxiliarySync", serverID)
	if len(listeners) > 0 || old.ID != "" {
		params["auxiliary"] = aux
	}
	return a.queue(ctx, u, serverID, "core.config.apply", params)
}
