package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) maintainOperations(ctx context.Context) {
	a.startJob(ctx, "operations", func(ctx context.Context) {
		a.runOperations(ctx, time.Now().UTC())
	})
}

func (a *App) runOperations(ctx context.Context, now time.Time) {
	actor := store.User{ID: "system", Role: "admin"}
	certs, err := a.DB.ListRecords(ctx, "certificates", "")
	if err != nil {
		return
	}
	for _, asset := range certs {
		if ctx.Err() != nil {
			return
		}
		if !boolean(asset.Data, "autoRenew") || disabledStatus(asset.Data) {
			continue
		}
		expires := dateTime(text(asset.Data, "expires"))
		if expires.IsZero() || expires.After(now.Add(30*24*time.Hour)) {
			continue
		}
		if !a.beginOperationAttempt(ctx, "certificate:"+asset.ID, now, 6*time.Hour) {
			continue
		}
		result, e := a.issueCertificate(ctx, actor, asset.ID, true)
		deploymentErrors, _ := result["deployment_errors"].([]any)
		if e == nil && (text(result, "deploymentError") != "" || len(deploymentErrors) > 0) {
			e = errors.New("证书已续期，但自动部署存在失败")
		}
		a.completeOperationAttempt(ctx, "certificate:"+asset.ID, result, e)
	}
	servers, err := a.DB.ListRecords(ctx, "servers", "")
	if err != nil {
		return
	}
	for _, server := range servers {
		if ctx.Err() != nil {
			return
		}
		ddns, _ := server.Data["ddns"].(map[string]any)
		if !boolean(ddns, "enabled") || disabledStatus(server.Data) {
			continue
		}
		interval := time.Duration(number(ddns, "interval")) * time.Second
		if interval < 60*time.Second {
			interval = 5 * time.Minute
		}
		if !a.beginOperationAttempt(ctx, "ddns:"+server.ID, now, interval) {
			continue
		}
		result, e := a.syncDDNS(ctx, actor, server.ID, nil)
		a.completeOperationAttempt(ctx, "ddns:"+server.ID, result, e)
	}
}

func (a *App) beginOperationAttempt(ctx context.Context, id string, now time.Time, interval time.Duration) bool {
	rec, err := a.DB.GetRecord(ctx, "_operationSchedule", id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false
	}
	if next := dateTime(text(rec.Data, "nextAttempt")); !next.IsZero() && now.Before(next) {
		return false
	}
	if rec.ID == "" {
		rec = store.Record{Collection: "_operationSchedule", ID: id, Data: map[string]any{}}
	}
	rec.Data["lastAttempt"] = now.Format(time.RFC3339Nano)
	rec.Data["nextAttempt"] = now.Add(interval).Format(time.RFC3339Nano)
	rec.Data["status"] = "running"
	_, err = a.DB.SaveRecord(ctx, rec)
	return err == nil
}

func (a *App) completeOperationAttempt(ctx context.Context, id string, result map[string]any, operationErr error) {
	rec, err := a.DB.GetRecord(ctx, "_operationSchedule", id)
	if err != nil {
		return
	}
	rec.Data["completedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Data["status"] = "success"
	delete(rec.Data, "error")
	if operationErr != nil {
		rec.Data["status"] = "failed"
		rec.Data["error"] = operationErr.Error()
	}
	rec.Data["result"] = result
	_, _ = a.DB.SaveRecord(ctx, rec)
}

func (a *App) registerOperations(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/certificates/sites", a.withAdmin(a.siteCertificates))
	mux.HandleFunc("PUT /api/admin/certificates/sites", a.withAdmin(a.configureSiteCertificates))
	mux.HandleFunc("POST /api/admin/certificates/upload", a.withAdmin(a.certificateUpload))
	mux.HandleFunc("GET /api/certificates/{id}/download", a.withAdmin(a.certificateDownload))
	mux.HandleFunc("POST /api/certificates/{id}/{operation}", a.withAdmin(func(w http.ResponseWriter, r *http.Request) {
		var params map[string]any
		if !decode(w, r, &params) {
			return
		}
		if params == nil {
			params = map[string]any{}
		}
		handled, result, err := a.operationsAction(r.Context(), current(r), actionInput{Action: "certificate." + r.PathValue("operation"), TargetID: r.PathValue("id"), Params: params})
		if !handled {
			fail(w, 404, "not_found", "证书操作不存在")
			return
		}
		if err != nil {
			fail(w, 400, "certificate_failed", err.Error())
			return
		}
		respond(w, 200, result)
	}))
	mux.HandleFunc("POST /api/servers/{id}/ddns", a.withAdmin(func(w http.ResponseWriter, r *http.Request) {
		var params map[string]any
		if !decode(w, r, &params) {
			return
		}
		result, err := a.syncDDNS(r.Context(), current(r), r.PathValue("id"), params)
		if err != nil {
			fail(w, 400, "ddns_failed", err.Error())
			return
		}
		respond(w, 200, result)
	}))
}

func (a *App) operationsAction(ctx context.Context, u store.User, in actionInput) (bool, map[string]any, error) {
	switch in.Action {
	case "certificate.issue", "certificate.renew", "certificate.upload", "certificate.deploy", "ddns.sync":
	default:
		return false, nil, nil
	}
	if u.Role != "admin" {
		return true, nil, errors.New("需要管理员权限")
	}
	var result map[string]any
	var err error
	switch in.Action {
	case "certificate.issue", "certificate.renew":
		result, err = a.issueCertificate(ctx, u, in.TargetID, in.Action == "certificate.renew")
	case "certificate.upload":
		certificateMu.Lock()
		defer certificateMu.Unlock()
		var asset store.Record
		asset, err = a.DB.GetRecord(ctx, "certificates", in.TargetID)
		if err == nil {
			asset.Data["autoRenew"] = false
			asset, err = a.saveCertificateMaterial(ctx, asset, text(in.Params, "certificate"), text(in.Params, "privateKey"), "manual")
		}
		if err == nil {
			result = map[string]any{"success": true, "row": rowOf(asset, false), "message": "证书与私钥已验证并保存"}
			if boolean(asset.Data, "autoDeploy") {
				deployment, e := a.deployCertificate(ctx, u, asset.ID, nil)
				if e != nil {
					result["deploymentError"] = e.Error()
				} else {
					result["tasks"] = deployment["tasks"]
					result["deployment_errors"] = deployment["deployment_errors"]
					result["siteDeployment"] = deployment["siteDeployment"]
				}
			}
		}
	case "certificate.deploy":
		result, err = a.deployCertificate(ctx, u, in.TargetID, in.Params)
	case "ddns.sync":
		result, err = a.syncDDNS(ctx, u, in.TargetID, in.Params)
	}
	if err == nil {
		a.audit(ctx, u, in.Action, in.TargetID, nil)
	}
	return true, result, err
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

var cloudflareID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func cloudflareRequest(ctx context.Context, client *http.Client, base, token, method, path string, input, out any) error {
	u, e := url.Parse(base)
	if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return errors.New("Cloudflare API必须使用HTTPS")
	}
	var body io.Reader
	if input != nil {
		raw, e := json.Marshal(input)
		if e != nil {
			return e
		}
		body = bytes.NewReader(raw)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	scoped := *client
	scoped.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	response, e := scoped.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if e := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope); e != nil {
		return errors.New("Cloudflare响应无法解析")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		message := "Cloudflare请求失败"
		if len(envelope.Errors) > 0 {
			message = fmt.Sprintf("Cloudflare错误%d: %s", envelope.Errors[0].Code, envelope.Errors[0].Message)
		}
		return errors.New(message)
	}
	if out != nil {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

func (a *App) syncDDNS(ctx context.Context, actor store.User, serverID string, params map[string]any) (map[string]any, error) {
	server, e := a.DB.GetRecord(ctx, "servers", serverID)
	if e != nil {
		return nil, e
	}
	settings, ok := server.Data["ddns"].(map[string]any)
	if !ok {
		return nil, errors.New("服务器尚未配置DDNS")
	}
	if provider := strings.ToLower(text(settings, "provider")); provider != "cloudflare" {
		return nil, errors.New("当前DDNS适配Cloudflare")
	}
	domain := strings.TrimSuffix(strings.ToLower(text(settings, "name")), ".")
	if _, e := certificateDomains(map[string]any{"domains": []string{domain}}); e != nil || strings.Contains(domain, "*") {
		return nil, errors.New("DDNS需要明确的主机域名")
	}
	kind := strings.ToUpper(text(settings, "type"))
	if kind == "" {
		kind = "A"
	}
	if kind != "A" && kind != "AAAA" {
		return nil, errors.New("DDNS记录类型仅支持A和AAAA")
	}
	value := text(params, "address")
	if value == "" {
		value = text(server.Data, "publicAddress")
	}
	if value == "" {
		value = text(server.Data, "address")
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	if ip == nil {
		return nil, errors.New("没有已确认的节点IP，请传address或配置服务器publicAddress")
	}
	if (kind == "A") != (ip.To4() != nil) {
		return nil, errors.New("地址与A/AAAA类型不匹配")
	}
	zoneID := text(settings, "zoneId")
	if !cloudflareID.MatchString(zoneID) {
		return nil, errors.New("Cloudflare Zone ID无效")
	}
	token := text(settings, "apiToken")
	if providerID := text(settings, "dnsProviderId"); providerID != "" {
		provider, e := a.DB.GetRecord(ctx, "dnsProviders", providerID)
		if e != nil {
			return nil, e
		}
		token = text(provider.Data, "apiToken")
		if token == "" {
			token = text(provider.Data, "credential")
		}
	}
	if token == "" {
		return nil, errors.New("缺少Cloudflare DNS编辑令牌")
	}
	base := defaultText(settings, "apiBaseURL", "https://api.cloudflare.com/client/v4")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var records []dnsRecord
	path := "/zones/" + zoneID + "/dns_records"
	if e := cloudflareRequest(ctx, a.client, base, token, "GET", path+"?type="+url.QueryEscape(kind)+"&name="+url.QueryEscape(domain), nil, &records); e != nil {
		return nil, e
	}
	matches := []dnsRecord{}
	for _, rec := range records {
		if rec.Type == kind && strings.TrimSuffix(strings.ToLower(rec.Name), ".") == domain {
			matches = append(matches, rec)
		}
	}
	if len(matches) > 1 {
		return nil, errors.New("同名同类型DNS记录不唯一，请先明确记录")
	}
	ttl := int(number(settings, "ttl"))
	if ttl == 0 {
		ttl = 120
	}
	if ttl != 1 && (ttl < 60 || ttl > 86400) {
		return nil, errors.New("TTL须为自动(1)或60至86400秒")
	}
	desired := dnsRecord{Type: kind, Name: domain, Content: ip.String(), TTL: ttl, Proxied: boolean(settings, "proxied")}
	changed := true
	method := "POST"
	if len(matches) == 1 {
		old := matches[0]
		if !cloudflareID.MatchString(old.ID) {
			return nil, errors.New("Cloudflare返回的记录ID无效")
		}
		if net.ParseIP(old.Content) != nil && net.ParseIP(old.Content).Equal(ip) && old.TTL == ttl && old.Proxied == desired.Proxied {
			changed = false
			desired = old
		} else {
			method = "PUT"
			path += "/" + old.ID
		}
	}
	if changed {
		if e := cloudflareRequest(ctx, a.client, base, token, method, path, desired, &desired); e != nil {
			return nil, e
		}
		if desired.Type != kind || strings.TrimSuffix(strings.ToLower(desired.Name), ".") != domain || net.ParseIP(desired.Content) == nil || !net.ParseIP(desired.Content).Equal(ip) {
			return nil, errors.New("DNS服务返回的结果与请求不一致")
		}
	}
	server.Data["ddnsLastResult"] = map[string]any{"recordId": desired.ID, "name": domain, "address": ip.String(), "changed": changed, "updatedAt": time.Now().UTC()}
	if _, e := a.DB.SaveRecord(ctx, server); e != nil {
		return nil, e
	}
	a.audit(ctx, actor, "ddns.sync", serverID, map[string]any{"name": domain, "changed": changed})
	return map[string]any{"success": true, "changed": changed, "recordId": desired.ID, "name": domain, "address": ip.String()}, nil
}
