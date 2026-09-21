package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/oschwald/maxminddb-golang"
)

const maxIPDatabaseSize = 32 << 20
const geoCacheTTL = 48 * time.Hour
const maxGeoCacheEntries = 4096
const defaultGeoIPURL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb"

type geoCacheEntry struct {
	country   string
	expiresAt time.Time
}

func (a *App) registerIPDatabase(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ip-databases", a.withAdmin(a.ipDatabaseList))
	mux.HandleFunc("POST /api/ip-databases", a.withAdmin(a.ipDatabaseUpload))
	mux.HandleFunc("POST /api/ip-databases/fetch", a.withAdmin(a.ipDatabaseFetch))
	mux.HandleFunc("POST /api/ip-databases/fetch-default", a.withAdmin(a.ipDatabaseFetchDefault))
	mux.HandleFunc("POST /api/ip-databases/{id}/activate", a.withAdmin(a.ipDatabaseActivate))
	mux.HandleFunc("DELETE /api/ip-databases/{id}", a.withAdmin(a.ipDatabaseDelete))
	mux.HandleFunc("GET /api/ip-lookup", a.withAdmin(a.ipLookup))
}
func ipDatabaseMetadata(record store.Record) map[string]any {
	out := clone(record.Data)
	delete(out, "body")
	out["id"] = record.ID
	out["createdAt"] = record.CreatedAt
	return out
}
func (a *App) ipDatabaseList(w http.ResponseWriter, r *http.Request) {
	rows, e := a.DB.ListRecords(r.Context(), "_ipDatabases", "")
	if e != nil {
		fail(w, 500, "storage_error", "读取IP库失败")
		return
	}
	active, _ := a.DB.GetRecord(r.Context(), "_ipDatabaseState", "active")
	out := []any{}
	for _, row := range rows {
		out = append(out, ipDatabaseMetadata(row))
	}
	respond(w, 200, map[string]any{"rows": out, "activeId": text(active.Data, "id"), "maximumBytes": maxIPDatabaseSize})
}
func (a *App) storeIPDatabase(ctx context.Context, name string, raw []byte) (store.Record, error) {
	if len(raw) == 0 || len(raw) > maxIPDatabaseSize {
		return store.Record{}, errors.New("IP数据库须为32MiB以内的MMDB文件")
	}
	reader, e := maxminddb.FromBytes(raw)
	if e != nil {
		return store.Record{}, errors.New("无法识别MMDB格式")
	}
	defer reader.Close()
	if e = reader.Verify(); e != nil {
		return store.Record{}, errors.New("IP数据库完整性校验失败")
	}
	sum := sha256.Sum256(raw)
	id := hex.EncodeToString(sum[:])
	old, _ := a.DB.GetRecord(ctx, "_ipDatabases", id)
	if old.ID != "" {
		return old, nil
	}
	versions, e := a.DB.ListRecords(ctx, "_ipDatabases", "")
	if e != nil {
		return store.Record{}, e
	}
	if len(versions) >= 3 {
		return store.Record{}, errors.New("最多保留3个IP库版本，请先删除不再使用的旧版本")
	}
	m := reader.Metadata
	return a.DB.SaveRecord(ctx, store.Record{Collection: "_ipDatabases", ID: id, Data: map[string]any{"name": name, "sha256": id, "size": len(raw), "databaseType": m.DatabaseType, "ipVersion": m.IPVersion, "buildTime": time.Unix(int64(m.BuildEpoch), 0).UTC(), "languages": m.Languages, "body": base64.StdEncoding.EncodeToString(raw)}})
}
func (a *App) ipDatabaseUpload(w http.ResponseWriter, r *http.Request) {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIPDatabaseSize))
	if e != nil {
		fail(w, 400, "too_large", "IP数据库超过32MiB")
		return
	}
	record, e := a.storeIPDatabase(r.Context(), r.URL.Query().Get("name"), raw)
	if e != nil {
		fail(w, 400, "invalid_database", e.Error())
		return
	}
	a.audit(r.Context(), current(r), "ipdb.upload", record.ID, nil)
	respond(w, 200, map[string]any{"row": ipDatabaseMetadata(record), "active": false})
}
func (a *App) ipDatabaseFetch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL    string
		SHA256 string
		Name   string
	}
	if !decode(w, r, &in) {
		return
	}
	if _, e := secureOrigin(in.URL); e != nil {
		fail(w, 400, "invalid_source", "数据库下载须使用HTTPS地址")
		return
	}
	want, e := hex.DecodeString(in.SHA256)
	if e != nil || len(want) != 32 {
		fail(w, 400, "hash_required", "请提供数据源公布的SHA256")
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), "GET", in.URL, nil)
	if e != nil {
		fail(w, 400, "invalid_source", "下载地址无效")
		return
	}
	client := *a.client
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) > 3 || next.URL.Scheme != via[0].URL.Scheme || next.URL.Host != via[0].URL.Host {
			return errors.New("数据库下载不允许跨来源跳转")
		}
		return nil
	}
	res, e := client.Do(req)
	if e != nil {
		fail(w, 502, "download_failed", "数据库下载失败")
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		fail(w, 502, "download_failed", "数据库下载未返回200")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxIPDatabaseSize+1))
	if e != nil || len(raw) > maxIPDatabaseSize {
		fail(w, 400, "invalid_database", "数据库超过32MiB或读取失败")
		return
	}
	sum := sha256.Sum256(raw)
	if !constant(hex.EncodeToString(sum[:]), strings.ToLower(in.SHA256)) {
		fail(w, 400, "checksum_mismatch", "数据库SHA256不匹配，当前版本保持不变")
		return
	}
	record, e := a.storeIPDatabase(r.Context(), in.Name, raw)
	if e != nil {
		fail(w, 400, "invalid_database", e.Error())
		return
	}
	a.audit(r.Context(), current(r), "ipdb.fetch", record.ID, nil)
	respond(w, 200, map[string]any{"row": ipDatabaseMetadata(record), "active": false})
}

func (a *App) ipDatabaseFetchDefault(w http.ResponseWriter, r *http.Request) {
	req, e := http.NewRequestWithContext(r.Context(), "GET", defaultGeoIPURL, nil)
	if e != nil {
		fail(w, 400, "invalid_source", "默认 IP 数据库地址无效")
		return
	}
	client := *a.client
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) > 3 || next.URL.Scheme != via[0].URL.Scheme || next.URL.Host != via[0].URL.Host {
			return errors.New("默认 IP 数据库不允许跨来源跳转")
		}
		return nil
	}
	res, e := client.Do(req)
	if e != nil {
		fail(w, 502, "download_failed", "默认 IP 数据库下载失败")
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fail(w, 502, "download_failed", "默认 IP 数据库下载未返回200")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxIPDatabaseSize+1))
	if e != nil || len(raw) > maxIPDatabaseSize {
		fail(w, 400, "invalid_database", "默认 IP 数据库超过32MiB或读取失败")
		return
	}
	record, e := a.storeIPDatabase(r.Context(), "GeoLite2-Country（Komari 默认）", raw)
	if e != nil {
		fail(w, 400, "invalid_database", e.Error())
		return
	}
	active, _ := a.DB.GetRecord(r.Context(), "_ipDatabaseState", "active")
	activeID := text(active.Data, "id")
	if activeID == "" {
		if _, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_ipDatabaseState", ID: "active", Version: active.Version, Data: map[string]any{"id": record.ID}}); e != nil {
			fail(w, 409, "conflict", "默认 IP 数据库已保存，但启用失败，请重试")
			return
		}
		activeID = record.ID
	}
	a.audit(r.Context(), current(r), "ipdb.fetch-default", record.ID, map[string]any{"source": defaultGeoIPURL})
	respond(w, 200, map[string]any{"row": ipDatabaseMetadata(record), "active": activeID == record.ID, "activeId": activeID, "source": defaultGeoIPURL})
}
func (a *App) readIPDatabase(ctx context.Context, id string) (*maxminddb.Reader, error) {
	record, e := a.DB.GetRecord(ctx, "_ipDatabases", id)
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(text(record.Data, "body"))
	if e != nil || len(raw) > maxIPDatabaseSize {
		return nil, errors.New("IP库内容损坏")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != id {
		return nil, errors.New("IP库校验失败")
	}
	return maxminddb.FromBytes(raw)
}

func mmdbCountryName(value any) string {
	entry, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	var names map[string]string
	switch raw := entry["names"].(type) {
	case map[string]any:
		names = make(map[string]string, len(raw))
		for key, value := range raw {
			if name, ok := value.(string); ok {
				names[key] = name
			}
		}
	case map[string]string:
		names = raw
	}
	for _, language := range []string{"zh-CN", "zh-TW", "en"} {
		if name, ok := names[language]; ok && strings.TrimSpace(name) != "" {
			return strings.TrimSpace(name)
		}
	}
	return ""
}

func (a *App) cachedGeoCountry(key string) (string, bool) {
	now := time.Now()
	a.geoCacheMu.Lock()
	defer a.geoCacheMu.Unlock()
	entry, ok := a.geoCache[key]
	if !ok {
		return "", false
	}
	if now.Before(entry.expiresAt) {
		return entry.country, true
	}
	delete(a.geoCache, key)
	return "", false
}

func (a *App) cacheGeoCountry(key, country string) {
	a.geoCacheMu.Lock()
	defer a.geoCacheMu.Unlock()
	if a.geoCache == nil {
		a.geoCache = map[string]geoCacheEntry{}
	}
	if len(a.geoCache) >= maxGeoCacheEntries {
		now := time.Now()
		for cachedKey, entry := range a.geoCache {
			if !now.Before(entry.expiresAt) {
				delete(a.geoCache, cachedKey)
			}
		}
		if len(a.geoCache) >= maxGeoCacheEntries {
			for cachedKey := range a.geoCache {
				delete(a.geoCache, cachedKey)
				break
			}
		}
	}
	a.geoCache[key] = geoCacheEntry{country: country, expiresAt: time.Now().Add(geoCacheTTL)}
}

func mmdbCountry(record map[string]any) string {
	for _, key := range []string{"country", "registered_country"} {
		if name := mmdbCountryName(record[key]); name != "" {
			return name
		}
	}
	return ""
}

func lookupHostIP(ctx context.Context, host string) []net.IP {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	if parsed, e := url.Parse(host); e == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else if parsedHost, _, e := net.SplitHostPort(host); e == nil {
		host = parsedHost
	}
	addresses, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP)
	}
	return ips
}

func (a *App) lookupHostCountry(ctx context.Context, host string) string {
	state, e := a.DB.GetRecord(ctx, "_ipDatabaseState", "active")
	if e != nil {
		return ""
	}
	databaseID := text(state.Data, "id")
	if databaseID == "" {
		return ""
	}
	ips := lookupHostIP(ctx, host)
	if len(ips) == 0 {
		return ""
	}
	reader, e := a.readIPDatabase(ctx, text(state.Data, "id"))
	if e != nil {
		return ""
	}
	defer reader.Close()
	for _, ip := range ips {
		cacheKey := databaseID + ":" + ip.String()
		if country, ok := a.cachedGeoCountry(cacheKey); ok {
			if country != "" {
				return country
			}
			continue
		}
		var record map[string]any
		if _, found, e := reader.LookupNetwork(ip, &record); e == nil && found {
			if country := mmdbCountry(record); country != "" {
				a.cacheGeoCountry(cacheKey, country)
				return country
			}
		}
		a.cacheGeoCountry(cacheKey, "")
	}
	return ""
}
func (a *App) ipDatabaseActivate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reader, e := a.readIPDatabase(r.Context(), id)
	if e != nil {
		fail(w, 400, "invalid_database", "IP数据库不存在或损坏")
		return
	}
	e = reader.Verify()
	reader.Close()
	if e != nil {
		fail(w, 400, "invalid_database", "IP数据库验证失败")
		return
	}
	state, _ := a.DB.GetRecord(r.Context(), "_ipDatabaseState", "active")
	_, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_ipDatabaseState", ID: "active", Version: state.Version, Data: map[string]any{"id": id}})
	if e != nil {
		fail(w, 409, "conflict", "IP库状态已更新，请重试")
		return
	}
	a.audit(r.Context(), current(r), "ipdb.activate", id, nil)
	respond(w, 200, map[string]any{"activeId": id})
}
func (a *App) ipDatabaseDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state, _ := a.DB.GetRecord(r.Context(), "_ipDatabaseState", "active")
	if text(state.Data, "id") == id {
		fail(w, 409, "in_use", "请先切换到另一版本再删除当前IP库")
		return
	}
	if e := a.DB.DeleteRecord(r.Context(), "_ipDatabases", id); e != nil {
		fail(w, 404, "not_found", "IP库不存在")
		return
	}
	a.audit(r.Context(), current(r), "ipdb.delete", id, nil)
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) ipLookup(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.URL.Query().Get("ip"))
	if ip == nil {
		fail(w, 400, "invalid_ip", "请输入IPv4或IPv6地址")
		return
	}
	state, e := a.DB.GetRecord(r.Context(), "_ipDatabaseState", "active")
	if e != nil {
		fail(w, 409, "database_missing", "尚未启用IP数据库")
		return
	}
	reader, e := a.readIPDatabase(r.Context(), text(state.Data, "id"))
	if e != nil {
		fail(w, 503, "database_unavailable", "当前IP库不可用，请重新上传或切换版本")
		return
	}
	defer reader.Close()
	var record map[string]any
	network, found, e := reader.LookupNetwork(ip, &record)
	if e != nil {
		fail(w, 400, "lookup_failed", e.Error())
		return
	}
	cidr := ""
	if network != nil {
		cidr = network.String()
	}
	respond(w, 200, map[string]any{"ip": ip.String(), "found": found, "network": cidr, "record": record, "databaseId": text(state.Data, "id"), "source": "local-mmdb"})
}
