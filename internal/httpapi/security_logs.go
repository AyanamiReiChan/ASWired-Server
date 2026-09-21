package httpapi

import (
	"context"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net"
	"net/http"
	"strings"
	"time"
)

func (a *App) securityEvent(r *http.Request, event, message string) {
	_ = a.writeEventLog(map[string]any{"category": "security", "level": "WARN", "event": event, "ip": requestIP(r), "message": message})
}
func (a *App) securityLists(ctx context.Context) ([]string, []string, error) {
	var config map[string]any
	err := a.DB.GetSetting(ctx, "securityAllowlist", &config)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	manual := stringList(config["addresses"])
	managed := []string{}
	seen := map[string]bool{}
	servers, err := a.DB.ListRecords(ctx, "servers", "")
	if err != nil {
		return nil, nil, err
	}
	for _, server := range servers {
		for _, key := range []string{"address", "ipv4", "ipv6"} {
			if ip := net.ParseIP(text(server.Data, key)); ip != nil && !seen[ip.String()] {
				seen[ip.String()] = true
				managed = append(managed, ip.String())
			}
		}
	}
	return manual, managed, nil
}
func addressMatches(address string, entries []string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, entry := range entries {
		if _, network, e := net.ParseCIDR(entry); e == nil && network.Contains(ip) {
			return true
		}
		if other := net.ParseIP(entry); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}
func (a *App) securityState(w http.ResponseWriter, r *http.Request) {
	manual, managed, err := a.securityLists(r.Context())
	if err != nil {
		fail(w, 500, "storage_error", "读取白名单失败")
		return
	}
	records, err := a.DB.ListRecords(r.Context(), "_securityBans", "")
	if err != nil {
		fail(w, 500, "storage_error", "读取封禁失败")
		return
	}
	bans := []map[string]any{}
	for _, record := range records {
		expires := dateTime(text(record.Data, "expiresAt"))
		if !expires.IsZero() && !expires.After(time.Now()) {
			continue
		}
		row := clone(record.Data)
		row["id"] = record.ID
		bans = append(bans, row)
	}
	respond(w, 200, map[string]any{"manual": manual, "managed": managed, "bans": bans, "currentIP": requestIP(r)})
}
func (a *App) securityAllowlist(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Addresses []string `json:"addresses"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Addresses) > 200 {
		fail(w, 400, "invalid_addresses", "最多 200 个地址")
		return
	}
	addresses := []string{}
	seen := map[string]bool{}
	for _, value := range input.Addresses {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			value = ip.String()
		} else if _, network, e := net.ParseCIDR(value); e == nil {
			value = network.String()
		} else {
			fail(w, 400, "invalid_ip", "请输入有效 IP 或 CIDR")
			return
		}
		if !seen[value] {
			addresses = append(addresses, value)
			seen[value] = true
		}
	}
	if err := a.DB.SetSetting(r.Context(), "securityAllowlist", map[string]any{"addresses": addresses}); err != nil {
		fail(w, 500, "storage_error", "保存白名单失败")
		return
	}
	a.securityEvent(r, "security.allowlist.updated", "订阅防护白名单已更新")
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) securityBan(w http.ResponseWriter, r *http.Request) {
	var input struct {
		IP        string `json:"ip"`
		Permanent bool   `json:"permanent"`
	}
	if !decode(w, r, &input) {
		return
	}
	ip := net.ParseIP(strings.TrimSpace(input.IP))
	if ip == nil {
		fail(w, 400, "invalid_ip", "请输入有效 IPv4 或 IPv6 地址")
		return
	}
	manual, managed, err := a.securityLists(r.Context())
	if err != nil {
		fail(w, 500, "storage_error", "读取白名单失败")
		return
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.String() == requestIP(r) || addressMatches(ip.String(), append(manual, managed...)) {
		fail(w, 409, "protected_ip", "当前访问地址、本机和白名单地址不能封禁")
		return
	}
	now := time.Now().UTC()
	kind := "临时"
	expires := ""
	if input.Permanent {
		kind = "永久"
	} else {
		expires = now.Add(time.Hour).Format(time.RFC3339)
	}
	id := hashOpaque(ip.String())
	old, e := a.DB.GetRecord(r.Context(), "_securityBans", id)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		fail(w, 500, "storage_error", "读取封禁失败")
		return
	}
	_, err = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_securityBans", ID: id, Version: old.Version, Data: map[string]any{"ip": ip.String(), "type": kind, "createdAt": now.Format(time.RFC3339), "expiresAt": expires, "failures": 0}})
	if err != nil {
		fail(w, 500, "storage_error", "保存封禁失败")
		return
	}
	a.securityEvent(r, "security.ban", kind+"封禁 "+ip.String())
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) securityUnban(w http.ResponseWriter, r *http.Request) {
	record, err := a.DB.GetRecord(r.Context(), "_securityBans", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "封禁不存在")
		return
	}
	if err = a.DB.DeleteRecord(r.Context(), "_securityBans", record.ID); err != nil {
		fail(w, 500, "storage_error", "解除封禁失败")
		return
	}
	a.securityEvent(r, "security.unban", "解除封禁 "+text(record.Data, "ip"))
	respond(w, 200, map[string]bool{"success": true})
}
func protectedPublicRoute(path string) bool {
	return path == "/api/login" || path == "/api/entry" || strings.HasPrefix(path, "/x/") || path == "/api/clash/subscribe" || path == "/api/merged-subscribe" || path == "/api/temporary-subscribe" || path == "/api/generated-subscribe"
}
func (a *App) securityBlocked(r *http.Request) bool {
	if !protectedPublicRoute(r.URL.Path) {
		return false
	}
	ip := requestIP(r)
	record, err := a.DB.GetRecord(r.Context(), "_securityBans", hashOpaque(ip))
	if err != nil {
		return false
	}
	expires := dateTime(text(record.Data, "expiresAt"))
	if !expires.IsZero() && !expires.After(time.Now()) {
		return false
	}
	manual, managed, err := a.securityLists(r.Context())
	if err == nil && addressMatches(ip, append(manual, managed...)) {
		return false
	}
	return true
}
