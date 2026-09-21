package httpapi

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

func inboundProtocol(row map[string]any) string {
	p := strings.ToLower(text(row, "protocol"))
	switch p {
	case "shadowsocks":
		return "ss"
	case "hy2":
		return "hysteria2"
	case "socks":
		return "socks5"
	}
	return p
}

func inboundTransport(row map[string]any) (string, string) {
	if strings.EqualFold(text(row, "transport"), "TCP / Reality") {
		return "tcp", "reality"
	}
	return strings.ToLower(text(row, "network")), strings.ToLower(text(row, "security"))
}

func validateManagedInboundProfile(row map[string]any) error {
	network, security := inboundTransport(row)
	if security == "reality" {
		return validateRealityInboundProfile(row)
	}
	p := inboundProtocol(row)
	switch p {
	case "vless", "vmess", "trojan":
		if network != "tcp" && network != "ws" && network != "grpc" {
			return errors.New("请选择 TCP、WebSocket 或 gRPC")
		}
		if security != "tls" && security != "none" {
			return errors.New("请选择 TLS 或无加密")
		}
		if p == "trojan" && security != "tls" {
			return errors.New("Trojan 入站需要 TLS")
		}
	case "hysteria2", "anytls":
		want := "tcp"
		if p == "hysteria2" {
			want = "hysteria"
		}
		if network != want || security != "tls" {
			return errors.New("此协议需要专用传输和 TLS")
		}
	case "ss", "snell", "socks5", "http":
		if network != "tcp" || (security != "none" && ((p != "http" && p != "socks5") || security != "tls")) {
			return errors.New("协议传输或安全设置不受支持")
		}
	default:
		return errors.New("该协议尚未接通受管入站")
	}
	if strings.TrimSpace(text(row, "transport")) == "" {
		return errors.New("请明确选择入站传输")
	}
	if strings.Join(strings.Fields(strings.ToLower(text(row, "transport"))), "") != network+"/"+security {
		return errors.New("传输标签与 network/security 不一致")
	}
	if strings.ContainsAny(text(row, "sni")+text(row, "path")+text(row, "hostHeader")+text(row, "serviceName"), "\r\n") {
		return errors.New("连接参数不能包含换行")
	}
	for _, key := range []string{"settings", "streamSettings"} {
		if value, exists := row[key]; exists && value != nil {
			object, ok := value.(map[string]any)
			if !ok || len(object) > 0 {
				return fmt.Errorf("%s 不允许覆盖，请使用协议专用字段", key)
			}
		}
	}
	if flow := text(row, "flow"); flow != "" && flow != "无" && (p != "vless" || network != "tcp" || security != "tls" || flow != "xtls-rprx-vision") {
		return errors.New("XTLS Vision 仅用于 VLESS TCP TLS/REALITY")
	}
	if security == "tls" && (text(row, "certificateFile") == "" || text(row, "keyFile") == "" || text(row, "sni") == "") {
		return errors.New("TLS 需要 SNI、Agent 证书路径和私钥路径")
	}
	if p == "hysteria2" {
		alpn := stringList(row["alpn"])
		if len(alpn) > 0 && (len(alpn) != 1 || alpn[0] != "h3") {
			return errors.New("Hysteria2 ALPN 必须为 h3")
		}
	}
	if p == "ss" {
		switch text(row, "method") {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
		default:
			return errors.New("请选择支持动态用户的 Shadowsocks AEAD 算法")
		}
	}
	if p == "snell" && number(row, "snellVersion") != 3 && number(row, "snellVersion") != 4 {
		return errors.New("Snell 版本须为 3 或 4")
	}
	return nil
}

func compileProtocolInbound(row map[string]any, clients []any) (map[string]any, error) {
	p := inboundProtocol(row)
	network, security := inboundTransport(row)
	settings := map[string]any{"clients": clients}
	switch p {
	case "vless":
		settings["decryption"] = "none"
	case "ss":
		p = "shadowsocks"
		settings["method"] = text(row, "method")
		settings["network"] = "tcp,udp"
	case "hysteria2":
		p = "hysteria"
		settings["version"] = 2
	case "socks5", "http":
		accounts := []any{}
		for _, raw := range clients {
			user := raw.(map[string]any)
			accounts = append(accounts, map[string]any{"user": text(user, "email"), "pass": text(user, "password")})
		}
		if len(accounts) == 0 {
			accounts = append(accounts, map[string]any{"user": "aswired-disabled", "pass": newID() + newID()})
		}
		settings = map[string]any{"accounts": accounts, "userLevel": 0}
		if p == "socks5" {
			p = "socks"
			settings["auth"] = "password"
			settings["udp"] = false
		}
	case "anytls", "snell":
		return nil, errors.New("辅助协议须通过服务器桥接配置发布")
	}
	stream := map[string]any{"network": network, "security": security}
	if security == "tls" {
		alpn := stringList(row["alpn"])
		if p == "hysteria" {
			alpn = []string{"h3"}
		}
		tls := map[string]any{"certificates": []any{map[string]any{"certificateFile": text(row, "certificateFile"), "keyFile": text(row, "keyFile")}}}
		if len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		stream["tlsSettings"] = tls
	}
	switch network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": defaultText(row, "path", "/")}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": text(row, "serviceName")}
	case "hysteria":
		stream["hysteriaSettings"] = map[string]any{"version": 2}
	}
	inbound := map[string]any{"tag": text(row, "tag"), "listen": defaultText(row, "listen", "0.0.0.0"), "port": number(row, "port"), "protocol": p, "settings": settings, "streamSettings": stream}
	if text(row, "sniffing") != "关闭" {
		inbound["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": text(row, "sniffing") == "仅路由"}
	}
	return inbound, nil
}

func (a *App) checkInboundCapabilities(ctx context.Context, serverID string) error {
	rows, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return err
	}
	a.mu.Lock()
	p := a.peers[serverID]
	caps := map[string]bool{}
	if p != nil {
		for k, v := range p.Capabilities {
			caps[k] = v
		}
	}
	a.mu.Unlock()
	for _, row := range rows {
		if text(row.Data, "serverId") != serverID || disabledStatus(row.Data) {
			continue
		}
		protocol := inboundProtocol(row.Data)
		if protocol == "hysteria2" && !caps["managed_protocols_v2"] {
			return errors.New("请先升级 Agent 以支持 Hysteria2 用户计量和会话撤销")
		}
		if auxiliaryProtocol(row.Data) && (!caps[protocol] || !caps["managed_protocols_v2"]) {
			return fmt.Errorf("Agent 未启用 %s 联合发布，请先升级 Agent 并配置 Mihomo", protocol)
		}
		if (protocol == "socks5" || protocol == "http") && !caps["managed_account_reload"] {
			return errors.New("请先升级 Agent 以支持 SOCKS/HTTP 受管账号同步")
		}
	}
	return nil
}
