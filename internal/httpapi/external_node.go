package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

// External nodes carry their own credentials. Managed inbounds keep their
// separate profile and subscription-specific credential projection.
func normalizedProxyNode(input map[string]any, requireUUID bool) (map[string]any, error) {
	if !requireUUID || boolean(input, "managedInbound") {
		return normalizedRealityNode(input, requireUUID)
	}
	row := clone(input)
	if raw := strings.TrimSpace(text(row, "uri")); raw != "" {
		parsed, err := parseImportedURI(raw)
		if err != nil {
			return nil, err
		}
		// Replacing a URI must not inherit credentials/options from the old protocol.
		for _, key := range []string{"id", "name", "tags", "region", "description", "status", "disabled", "weight", "visible", "sortOrder", "source", "sourceId", "importedName", "sourceMissing", "recordVersion", "latency", "latencyStatus", "latencyTestedAt", "latencyKind", "latencyError", "testedAt"} {
			if value, ok := row[key]; ok {
				parsed[key] = value
			}
		}
		row = parsed
	}
	if text(row, "host") == "" {
		row["host"] = row["server"]
	}
	if text(row, "protocol") == "" {
		row["protocol"] = row["type"]
	}
	protocol := strings.ToLower(strings.TrimSpace(text(row, "protocol")))
	switch protocol {
	case "shadowsocks":
		protocol = "ss"
	case "hy2":
		protocol = "hysteria2"
	case "socks":
		protocol = "socks5"
	case "wg":
		protocol = "wireguard"
	}
	switch protocol {
	case "vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "socks5", "http", "anytls", "snell", "tuic", "wireguard":
	default:
		return nil, errors.New("不支持的节点协议")
	}
	row["protocol"] = protocol
	for _, key := range []string{"port", "alterId", "snellVersion", "version", "mtu", "up", "down"} {
		if value, ok := row[key].(string); ok && value != "" {
			n, err := strconv.ParseFloat(value, 64)
			if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
				return nil, fmt.Errorf("节点 %s 须为数字", key)
			}
			row[key] = n
		}
	}
	for _, pair := range [][2]string{{"servername", "sni"}, {"cipher", "method"}, {"psk", "password"}, {"client-fingerprint", "fingerprint"}, {"private-key", "privateKey"}, {"public-key", "publicKey"}, {"pre-shared-key", "preSharedKey"}, {"auth-str", "password"}} {
		if text(row, pair[1]) == "" && row[pair[0]] != nil {
			row[pair[1]] = row[pair[0]]
		}
	}
	if boolean(row, "tls") && text(row, "security") == "" {
		row["security"] = "tls"
	}
	if opts, ok := row["reality-opts"].(map[string]any); ok {
		row["security"], row["publicKey"], row["shortId"] = "reality", opts["public-key"], opts["short-id"]
	}
	if opts, ok := row["ws-opts"].(map[string]any); ok {
		row["network"], row["path"] = "ws", opts["path"]
		if headers, ok := opts["headers"].(map[string]any); ok {
			row["hostHeader"] = headers["Host"]
		}
		for key := range opts {
			if key != "path" && key != "headers" {
				return nil, fmt.Errorf("暂不支持 WS 参数 %s", key)
			}
		}
		if headers, ok := opts["headers"].(map[string]any); ok {
			for key := range headers {
				if key != "Host" {
					return nil, fmt.Errorf("暂不支持 WS 请求头 %s", key)
				}
			}
		}
	}
	if opts, ok := row["grpc-opts"].(map[string]any); ok {
		row["network"], row["serviceName"] = "grpc", opts["grpc-service-name"]
		for key := range opts {
			if key != "grpc-service-name" {
				return nil, fmt.Errorf("暂不支持 gRPC 参数 %s", key)
			}
		}
	}
	for _, key := range []string{"settings", "streamSettings", "peers", "smux", "mux", "packet-encoding", "dialer-proxy", "routing-mark", "interface-name"} {
		if nonemptyNodeExtension(row[key]) {
			return nil, fmt.Errorf("暂不支持节点参数 %s", key)
		}
	}
	host := strings.TrimSpace(text(row, "host"))
	if host == "" || strings.ContainsAny(host, " /\\@?#=,\r\n\t") {
		return nil, errors.New("节点地址无效")
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		if _, err := realityDomain(host); err != nil {
			return nil, errors.New("节点地址须为 IP 或域名")
		}
	}
	row["host"] = strings.Trim(host, "[]")
	port := number(row, "port")
	if port < 1 || port > 65535 || math.Trunc(port) != port {
		return nil, errors.New("节点端口须为 1 至 65535 整数")
	}
	if protocol == "vless" || protocol == "vmess" || protocol == "tuic" {
		if !nodeUUIDPattern.MatchString(text(row, "uuid")) {
			return nil, errors.New("节点需要有效 UUID")
		}
	}
	if protocol == "wireguard" {
		if mtu := number(row, "mtu"); row["mtu"] != nil && (mtu < 576 || mtu > 65535 || mtu != math.Trunc(mtu)) {
			return nil, errors.New("WireGuard MTU 须为 576 至 65535 的整数")
		}
		for _, key := range []string{"privateKey", "publicKey", "preSharedKey"} {
			value := text(row, key)
			if key == "preSharedKey" && value == "" {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(decoded) != 32 {
				return nil, fmt.Errorf("WireGuard %s 须为 32 字节 Base64 密钥", key)
			}
		}
		if text(row, "ip") == "" && text(row, "ipv6") == "" {
			return nil, errors.New("WireGuard 需要本地 ip 或 ipv6 地址")
		}
		for _, key := range []string{"ip", "ipv6"} {
			value := text(row, key)
			if value == "" {
				continue
			}
			ip := net.ParseIP(value)
			if ip == nil {
				ip, _, _ = net.ParseCIDR(value)
			}
			if ip == nil || (key == "ip") != (ip.To4() != nil) {
				return nil, errors.New("WireGuard 本地地址无效")
			}
			row[key] = ip.String()
		}
		if row["reserved"] != nil {
			values, ok := row["reserved"].([]any)
			if !ok || len(values) != 3 {
				return nil, errors.New("WireGuard reserved 须为三个字节")
			}
			for _, value := range values {
				switch value.(type) {
				case int, int64, float64, json.Number:
				default:
					return nil, errors.New("WireGuard reserved 须为数字字节")
				}
				n := number(map[string]any{"n": value}, "n")
				if n < 0 || n > 255 || n != math.Trunc(n) {
					return nil, errors.New("WireGuard reserved 无效")
				}
			}
		}
	}
	connection := clone(row)
	delete(connection, "inboundId")
	client, err := clientNodeFor(store.Record{Data: connection}, store.Record{})
	if err != nil {
		return nil, err
	}
	if client.Network == "raw" {
		client.Network = "tcp"
	}
	if client.Security != "" && client.Security != "none" && client.Security != "tls" && client.Security != "reality" {
		return nil, errors.New("节点安全类型无效")
	}
	if (protocol == "trojan" || protocol == "anytls" || protocol == "tuic" || protocol == "hysteria2") && client.Security != "tls" {
		return nil, errors.New("该协议需要 TLS")
	}
	if protocol == "vmess" && number(row, "alterId") != math.Trunc(number(row, "alterId")) {
		return nil, errors.New("VMess alterId 须为整数")
	}
	if client.Flow != "" && (client.Protocol != "vless" || client.Network != "tcp" || client.Security != "reality" && client.Security != "tls") {
		return nil, errors.New("Vision Flow 需要 VLESS TCP TLS/REALITY")
	}
	if client.Security == "reality" {
		if protocol != "vless" {
			return nil, errors.New("REALITY 仅支持 VLESS 节点")
		}
		check := clone(row)
		check["network"], check["transport"] = "tcp", "TCP / Reality"
		delete(check, "uri")
		delete(check, "ws-opts")
		delete(check, "grpc-opts")
		if _, err := normalizedRealityNode(check, true); err != nil {
			return nil, err
		}
	}
	if protocol != "vless" && protocol != "vmess" && protocol != "trojan" && client.Network != "tcp" {
		return nil, errors.New("该协议不支持所选传输")
	}
	if !compatible(client, "clash") {
		return nil, errors.New("不支持此协议、传输或安全组合")
	}
	row["protocol"] = map[string]string{"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks", "hysteria": "Hysteria", "hysteria2": "Hysteria2", "socks5": "SOCKS5", "http": "HTTP", "anytls": "AnyTLS", "snell": "Snell", "tuic": "TUIC", "wireguard": "WireGuard"}[protocol]
	row["network"], row["security"], row["transport"] = client.Network, client.Security, strings.ToUpper(client.Network)
	switch protocol {
	case "hysteria", "hysteria2", "tuic", "wireguard":
		row["transport"] = "UDP"
	}
	if client.Security != "" && client.Security != "none" {
		row["transport"] = text(row, "transport") + " / " + strings.ToUpper(client.Security)
	}
	return row, nil
}

// YAML also accepts JSON. URI lists retain per-line errors for import preview.
func nodeImportEntries(content string) ([]map[string]any, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, errors.New("请填写节点链接或配置")
	}
	var document any
	if yaml.Unmarshal([]byte(content), &document) == nil {
		var values []any
		switch parsed := document.(type) {
		case map[string]any:
			if proxies, ok := parsed["proxies"].([]any); ok {
				values = proxies
			} else if parsed["type"] != nil || parsed["protocol"] != nil {
				values = []any{parsed}
			}
		case []any:
			values = parsed
		}
		if values != nil {
			rows := make([]map[string]any, 0, len(values))
			for _, value := range values {
				row, ok := value.(map[string]any)
				if !ok {
					return nil, errors.New("节点配置列表必须包含对象")
				}
				rows = append(rows, row)
			}
			return rows, nil
		}
	}
	if !strings.Contains(content, "://") {
		if decoded, err := decodeSubscriptionBase64(content); err == nil {
			content = decoded
		}
	}
	rows := []map[string]any{}
	for _, line := range strings.Split(content, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			rows = append(rows, map[string]any{"uri": line})
		}
	}
	return rows, nil
}
