package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net"
	"regexp"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var errNodeProfile = errors.New("节点仅支持 VLESS TCP REALITY，请提供对应完整配置；旧节点可停用或删除")
var nodeUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func normalizedRealityNode(input map[string]any, requireUUID bool) (map[string]any, error) {
	row := clone(input)
	if raw := strings.TrimSpace(text(row, "uri")); raw != "" {
		parsed, err := parseImportedURI(raw)
		if err != nil {
			return nil, err
		}
		name := text(row, "name")
		for _, key := range []string{"host", "server", "port", "protocol", "type", "uuid", "password", "username", "network", "transport", "security", "sni", "servername", "publicKey", "shortId", "flow", "fingerprint", "reality-opts", "tls", "ws-opts", "grpc-opts", "streamSettings", "settings", "path", "serviceName", "alpn", "skipCertVerify", "skip-cert-verify", "insecure", "method", "cipher", "psk", "plugin", "plugin_opts", "plugin-opts", "pluginOptions", "obfs", "obfsPassword", "obfs-password", "congestionController", "congestionControl", "congestion-controller", "congestion_control", "udpRelayMode", "udp-relay-mode", "udp_relay_mode", "zero_rtt_handshake", "reduce-rtt", "ports", "server_ports", "hop-interval", "hop_interval", "realm-opts", "obfs-opts", "obfs-min-packet-size", "obfs-max-packet-size", "udp_over_stream", "disable-sni", "heartbeat", "heartbeat-interval", "snellVersion", "version"} {
			delete(row, key)
		}
		for key, value := range parsed {
			row[key] = value
		}
		if name != "" {
			row["name"] = name
		}
		row["network"] = defaultText(parsed, "network", "tcp")
		row["security"] = text(parsed, "security")
		row["sni"] = text(parsed, "sni")
		row["publicKey"] = text(parsed, "publicKey")
		row["shortId"] = text(parsed, "shortId")
		row["flow"] = text(parsed, "flow")
		delete(row, "transport")
	}
	if text(row, "host") == "" {
		row["host"] = text(row, "server")
	}
	if text(row, "protocol") == "" {
		row["protocol"] = text(row, "type")
	}
	if opts, ok := row["reality-opts"].(map[string]any); ok {
		if text(row, "publicKey") == "" {
			row["publicKey"] = text(opts, "public-key")
		}
		if text(row, "shortId") == "" {
			row["shortId"] = text(opts, "short-id")
		}
		if text(row, "security") == "" {
			row["security"] = "reality"
		}
	}
	if text(row, "sni") == "" {
		row["sni"] = text(row, "servername")
	}
	if !requireUUID {
		names := stringList(row["sni"])
		if len(names) == 0 {
			names = stringList(row["serverNames"])
		}
		if len(names) > 0 {
			row["sni"] = names[0]
		}
		if text(row, "flow") == "无" {
			row["flow"] = ""
		}
	}
	transport := strings.Join(strings.Fields(strings.ToLower(text(row, "transport"))), "")
	if transport != "" && transport != "tcp" && transport != "raw" && transport != "tcp/reality" && transport != "raw/reality" {
		return nil, errNodeProfile
	}
	if text(row, "security") == "" && strings.HasSuffix(transport, "/reality") {
		row["security"] = "reality"
	}
	network := strings.ToLower(strings.TrimSpace(defaultText(row, "network", "tcp")))
	if !strings.EqualFold(strings.TrimSpace(text(row, "protocol")), "vless") || network != "tcp" && network != "raw" || !strings.EqualFold(strings.TrimSpace(text(row, "security")), "reality") {
		return nil, errNodeProfile
	}
	for _, key := range []string{"ws-opts", "grpc-opts", "streamSettings", "settings", "plugin", "plugin_opts", "plugin-opts", "pluginOptions", "obfs", "obfsPassword", "obfs-password", "congestionController", "congestionControl", "congestion-controller", "congestion_control", "udpRelayMode", "udp-relay-mode", "udp_relay_mode", "ports", "server_ports", "hop-interval", "hop_interval", "realm-opts", "obfs-opts", "udp_over_stream", "disable-sni"} {
		if value, ok := row[key]; ok && nonemptyNodeExtension(value) {
			return nil, errNodeProfile
		}
	}
	host := strings.TrimSpace(text(row, "host"))
	if host == "" || strings.ContainsAny(host, " /\\@?#=,\r\n\t") {
		return nil, errors.New("节点地址无效")
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		if _, err := realityDomain(host); err != nil {
			return nil, errors.New("节点地址须为IP或完整域名")
		}
	}
	port := number(row, "port")
	if port < 1 || port > 65535 || math.Trunc(port) != port {
		return nil, errors.New("节点端口须为1至65535整数")
	}
	if requireUUID && !nodeUUIDPattern.MatchString(text(row, "uuid")) {
		return nil, errors.New("VLESS 节点需要有效 UUID")
	}
	sni, err := realityDomain(text(row, "sni"))
	if err != nil {
		return nil, errors.New("REALITY 节点需要有效 SNI 域名")
	}
	key := strings.TrimSpace(text(row, "publicKey"))
	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != key {
		return nil, errors.New("REALITY 公钥须为32字节 Base64URL 密钥")
	}
	sid := text(row, "shortId")
	if len(sid) > 16 || len(sid)%2 != 0 {
		return nil, errors.New("REALITY Short ID须为最多16位偶数长度十六进制")
	}
	if _, err := hex.DecodeString(sid); err != nil {
		return nil, errors.New("REALITY Short ID包含非法字符")
	}
	flow := text(row, "flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return nil, errors.New("REALITY Flow仅支持空值或xtls-rprx-vision")
	}
	row["protocol"] = "VLESS"
	row["network"] = "tcp"
	row["security"] = "reality"
	row["transport"] = "TCP / Reality"
	row["host"] = host
	row["sni"] = sni
	row["publicKey"] = key
	return row, nil
}

func legacyProxyUnchanged(next, previous map[string]any) bool {
	clean := func(row map[string]any) []byte {
		row = clone(row)
		for _, key := range []string{"name", "description", "status", "tags", "region", "disabled", "id", "recordVersion", "createdAt", "updatedAt", "canManage"} {
			delete(row, key)
		}
		raw, _ := json.Marshal(row)
		return raw
	}
	return string(clean(next)) == string(clean(previous))
}

func (a *App) realitySubscriptionNode(ctx context.Context, record, subscription store.Record) (clientNode, error) {
	managed := boolean(record.Data, "managedInbound")
	if managed {
		inbound, err := a.DB.GetRecord(ctx, "inbounds", text(record.Data, "inboundId"))
		if err != nil || disabledStatus(inbound.Data) || validateManagedInboundProfile(inbound.Data) != nil {
			return clientNode{}, errNodeProfile
		}
		record.Data = clone(record.Data)
		delete(record.Data, "settings")
		delete(record.Data, "streamSettings")
		names := stringList(record.Data["sni"])
		if len(names) == 0 {
			names = stringList(record.Data["serverNames"])
		}
		if len(names) > 0 {
			record.Data["sni"] = names[0]
		}
		if text(record.Data, "flow") == "无" {
			record.Data["flow"] = ""
		}
	}
	if !managed {
		normalized, err := normalizedProxyNode(record.Data, true)
		if err != nil {
			return clientNode{}, err
		}
		record.Data = normalized
	}
	client, err := clientNodeFor(record, subscription)
	if err != nil {
		return clientNode{}, err
	}
	return a.relayClient(ctx, record.ID, client)
}

func validateRealityOutbound(row map[string]any) error {
	protocol := strings.ToLower(text(row, "protocol"))
	if protocol == "freedom" || protocol == "blackhole" {
		return nil
	}
	if protocol != "vless" {
		return errors.New("代理出站仅支持 VLESS TCP REALITY；直连和阻断仍可使用")
	}
	stream, ok := row["streamSettings"].(map[string]any)
	if !ok {
		return errNodeProfile
	}
	network := strings.ToLower(defaultText(stream, "network", "tcp"))
	if network != "tcp" && network != "raw" || text(stream, "security") != "reality" {
		return errNodeProfile
	}
	for key := range stream {
		if key != "network" && key != "security" && key != "realitySettings" && key != "sockopt" {
			return errNodeProfile
		}
	}
	reality, ok := stream["realitySettings"].(map[string]any)
	if !ok {
		return errors.New("代理出站缺少 REALITY 设置")
	}
	publicKey := defaultText(reality, "publicKey", text(reality, "password"))
	if text(reality, "publicKey") != "" && text(reality, "password") != "" && text(reality, "publicKey") != text(reality, "password") {
		return errors.New("REALITY 公钥字段不一致")
	}
	settings, ok := row["settings"].(map[string]any)
	if !ok {
		return errors.New("代理出站缺少 vnext 配置")
	}
	servers, ok := settings["vnext"].([]any)
	if !ok || len(servers) == 0 {
		return errors.New("代理出站需要至少一个 vnext 目标")
	}
	for _, raw := range servers {
		server, ok := raw.(map[string]any)
		if !ok {
			return errNodeProfile
		}
		users, ok := server["users"].([]any)
		if !ok || len(users) == 0 {
			return errors.New("代理出站缺少用户 UUID")
		}
		for _, rawUser := range users {
			user, ok := rawUser.(map[string]any)
			if !ok {
				return errNodeProfile
			}
			if encryption := text(user, "encryption"); encryption != "" && encryption != "none" {
				return errors.New("VLESS 出站 encryption 仅支持 none")
			}
			data := map[string]any{"protocol": "VLESS", "host": server["address"], "port": server["port"], "uuid": user["id"], "flow": user["flow"], "network": "tcp", "security": "reality", "sni": reality["serverName"], "publicKey": publicKey, "shortId": reality["shortId"]}
			if _, err := normalizedRealityNode(data, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func nonemptyNodeExtension(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	default:
		return configuredExtension(value)
	}
}
