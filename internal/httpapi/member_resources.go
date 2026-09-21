package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net"
	"net/http"
	"strconv"
	"time"
)

func memberNodeRow(record store.Record) map[string]any {
	row := map[string]any{"id": record.ID, "subscriptionAuthorized": true, "canManage": false, "canTest": true}
	for _, field := range []string{"name", "region", "protocol", "source", "tags", "status", "latency", "latencyStatus"} {
		if value, exists := record.Data[field]; exists {
			row[field] = value
		}
	}
	return row
}
func (a *App) memberNodeAllowed(ctx context.Context, userID, nodeID string) bool {
	subscriptions, err := a.DB.ListRecords(ctx, "subscriptions", userID)
	if err != nil {
		return false
	}
	for _, sub := range subscriptions {
		nodes, err := a.eligibleNodes(ctx, sub)
		if err != nil {
			continue
		}
		for _, node := range nodes {
			if node.ID == nodeID {
				return true
			}
		}
	}
	return false
}
func memberResource(collection string) bool { return collection == "nodes" }
func (a *App) prepareMemberResource(r *http.Request, collection string, row map[string]any, previous store.Record, exists bool) (map[string]any, error) {
	u := current(r)
	if !memberResource(collection) || exists && previous.OwnerID != u.ID {
		return nil, errors.New("只能修改自己的节点")
	}
	member, _ := a.DB.GetRecord(r.Context(), "members", u.ID)
	quotas, _ := member.Data["resourceQuotas"].(map[string]any)
	quota := 50
	if _, ok := quotas[collection]; ok {
		quota = int(number(quotas, collection))
	}
	if !exists {
		records, e := a.DB.ListRecords(r.Context(), collection, u.ID)
		if e != nil {
			return nil, e
		}
		if quota <= 0 || len(records) >= quota {
			return nil, errors.New("已达到账户资源配额")
		}
	}
	clean := map[string]any{}
	fields := []string{"name", "description", "status", "tags", "region", "host", "port", "protocol", "uuid", "password", "username", "uri", "network", "security", "sni", "publicKey", "shortId", "flow", "fingerprint", "path", "serviceName", "method", "cipher", "plugin", "plugin-opts", "alpn", "skipCertVerify", "obfs", "obfsPassword", "congestionController", "udpRelayMode"}
	for _, field := range fields {
		if value, ok := row[field]; ok {
			clean[field] = value
		}
	}
	if exists && disabledStatus(row) {
		if _, err := normalizedProxyNode(previous.Data, true); err != nil && legacyProxyUnchanged(row, previous.Data) {
			return row, nil
		}
	}
	if raw := text(clean, "uri"); raw != "" {
		parsed, e := parseImportedURI(raw)
		if e != nil {
			return nil, e
		}
		name := text(clean, "name")
		for key, value := range parsed {
			clean[key] = value
		}
		if name != "" {
			clean["name"] = name
		}
	}
	if text(clean, "host") == "" || number(clean, "port") < 1 || number(clean, "port") > 65535 {
		return nil, errors.New("节点地址与端口无效")
	}
	clean["source"] = "个人节点"
	return clean, nil
}
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	if _, e = strconv.Atoi(port); e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, errors.New("destination has no address")
	}
	for _, value := range ips {
		ip := value.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("成员资源不能请求私网、回环或链路本地地址")
		}
		for _, cidr := range []string{"0.0.0.0/8", "240.0.0.0/4", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			_, reserved, _ := net.ParseCIDR(cidr)
			if reserved.Contains(ip) {
				return nil, errors.New("成员资源不能请求保留地址")
			}
		}
	}
	var last error
	for _, ip := range ips {
		conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, fmt.Errorf("外部连接失败: %w", last)
}
func (a *App) memberActionAllowed(r *http.Request, in actionInput) bool {
	if in.Action != "node.health.check" {
		return false
	}
	return a.memberNodeAllowed(r.Context(), current(r).ID, in.TargetID)
}

func (a *App) memberQuotas(ctx context.Context, id string) map[string]int {
	member, _ := a.DB.GetRecord(ctx, "members", id)
	raw, _ := member.Data["resourceQuotas"].(map[string]any)
	quotas := map[string]int{"nodes": 50, "sources": 10}
	for key := range quotas {
		if _, ok := raw[key]; ok {
			quotas[key] = int(number(raw, key))
		}
	}
	return quotas
}
