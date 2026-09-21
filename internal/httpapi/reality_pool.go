package httpapi

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

const realityPoolCollection = "_realityTargets"

func (a *App) registerRealityPool(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/reality-targets/scan", a.withAdmin(a.realityPoolScan))
	mux.HandleFunc("POST /api/reality-targets/scan/import", a.withAdmin(a.realityPoolScanImport))
	mux.HandleFunc("GET /api/reality-targets", a.withAdmin(a.realityPoolList))
	mux.HandleFunc("PUT /api/reality-targets/allowlist", a.withAdmin(a.realityPoolAllowlist))
	mux.HandleFunc("PUT /api/reality-targets/{id}", a.withAdmin(a.realityPoolUpdate))
	mux.HandleFunc("DELETE /api/reality-targets/{id}", a.withAdmin(a.realityPoolDelete))
	mux.HandleFunc("POST /api/reality-targets/{id}/probe", a.withAdmin(a.realityPoolProbe))
	mux.HandleFunc("POST /api/reality-targets/{id}/review", a.withAdmin(a.realityPoolReview))
}

func realityDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	if len(domain) > 253 || len(domain) < 4 || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil || strings.HasSuffix(domain, ".") || strings.ContainsAny(domain, "/:@?#\\ \t\r\n*") {
		return "", errors.New("请填写完整域名，不含协议、端口、路径、IP或通配符")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("域名标签无效")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("域名须使用ASCII或Punycode")
			}
		}
	}
	return domain, nil
}
func (a *App) realityAllowed(ctx context.Context) (map[string]bool, []string, error) {
	rec, e := a.DB.GetRecord(ctx, "_realityTargetSettings", "allowlist")
	if errors.Is(e, store.ErrNotFound) {
		return map[string]bool{}, []string{}, nil
	}
	if e != nil {
		return nil, nil, e
	}
	values := stringList(rec.Data["domains"])
	allowed := map[string]bool{}
	for _, domain := range values {
		allowed[domain] = true
	}
	return allowed, values, nil
}
func realityAvailable(rec store.Record, allowed map[string]bool) bool {
	probe, _ := rec.Data["lastProbe"].(map[string]any)
	return boolean(rec.Data, "enabled") && text(rec.Data, "status") == "approved" && allowed[text(rec.Data, "domain")] && boolean(probe, "success") && time.Now().Before(dateTime(text(probe, "certificateExpires")))
}
func realityPoolRow(rec store.Record, allowed map[string]bool) map[string]any {
	row := rowOf(rec, false)
	row["available"] = realityAvailable(rec, allowed)
	row["allowed"] = allowed[text(rec.Data, "domain")]
	return row
}

func (a *App) realityPoolList(w http.ResponseWriter, r *http.Request) {
	allowed, domains, e := a.realityAllowed(r.Context())
	if e != nil {
		fail(w, 503, "storage_error", "目标池暂不可用")
		return
	}
	records, e := a.DB.ListRecords(r.Context(), realityPoolCollection, "")
	if e != nil {
		fail(w, 503, "storage_error", "目标池暂不可用")
		return
	}
	rows := []any{}
	for _, rec := range records {
		rows = append(rows, realityPoolRow(rec, allowed))
	}
	respond(w, 200, map[string]any{"rows": rows, "allowedDomains": domains})
}
func (a *App) realityPoolAllowlist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domains []string `json:"domains"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Domains) > 200 {
		fail(w, 400, "invalid_domains", "最多允许200个域名")
		return
	}
	domains := []string{}
	seen := map[string]bool{}
	for _, raw := range in.Domains {
		domain, e := realityDomain(raw)
		if e != nil {
			fail(w, 400, "invalid_domain", e.Error())
			return
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	old, _ := a.DB.GetRecord(r.Context(), "_realityTargetSettings", "allowlist")
	if _, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: "_realityTargetSettings", ID: "allowlist", Version: old.Version, Data: map[string]any{"domains": domains}}); e != nil {
		fail(w, 409, "conflict", "允许列表已更新，请重试")
		return
	}
	a.audit(r.Context(), current(r), "reality.allowlist.update", "allowlist", nil)
	respond(w, 200, map[string]any{"domains": domains})
}
func probeRealityTLS(ctx context.Context, domain string, dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) (map[string]any, error) {
	target, err := parseRealityScanTarget(net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, err
	}
	return probeRealityStored(ctx, target, domain, dial, roots)
}
func (a *App) realityPoolProbe(w http.ResponseWriter, r *http.Request) {
	rec, e := a.DB.GetRecord(r.Context(), realityPoolCollection, r.PathValue("id"))
	if e != nil {
		fail(w, 404, "not_found", "目标不存在")
		return
	}
	allowed, _, e := a.realityAllowed(r.Context())
	if e != nil || !allowed[text(rec.Data, "domain")] {
		fail(w, 403, "domain_denied", "域名不在允许列表中")
		return
	}
	target, err := realityRecordTarget(rec)
	if err != nil {
		fail(w, 400, "invalid_target", "已保存的目标地址无效")
		return
	}
	dial, roots := a.realityTransport()
	result, probeErr := probeRealityStored(r.Context(), target, text(rec.Data, "domain"), dial, roots)
	if probeErr != nil {
		if result == nil {
			result = map[string]any{"success": false, "error": probeErr.Error(), "checkedAt": time.Now().UTC().Format(time.RFC3339Nano)}
		}
		rec.Data["enabled"] = false
	}
	rec.Data["lastProbe"] = result
	if rec, e = a.DB.SaveRecord(r.Context(), rec); e != nil {
		fail(w, 409, "conflict", "目标记录已改变，请重新读取")
		return
	}
	a.audit(r.Context(), current(r), "reality.target.probe", rec.ID, map[string]any{"success": probeErr == nil})
	respond(w, 200, map[string]any{"success": probeErr == nil, "row": realityPoolRow(rec, allowed), "result": result})
}
func (a *App) realityPoolReview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approve bool `json:"approve"`
	}
	if !decode(w, r, &in) {
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), realityPoolCollection, r.PathValue("id"))
	if e != nil {
		fail(w, 404, "not_found", "目标不存在")
		return
	}
	allowed, _, e := a.realityAllowed(r.Context())
	if e != nil {
		fail(w, 503, "storage_error", "读取允许列表失败")
		return
	}
	if in.Approve {
		probe, _ := rec.Data["lastProbe"].(map[string]any)
		if !allowed[text(rec.Data, "domain")] || !boolean(probe, "success") || time.Since(dateTime(text(probe, "checkedAt"))) > 15*time.Minute || !time.Now().Before(dateTime(text(probe, "certificateExpires"))) {
			fail(w, 400, "probe_required", "批准前须对允许域名完成15分钟内的有效探测")
			return
		}
		rec.Data["status"] = "approved"
		rec.Data["enabled"] = true
	} else {
		rec.Data["status"] = "rejected"
		rec.Data["enabled"] = false
	}
	rec.Data["reviewerId"] = current(r).ID
	rec.Data["reviewedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec, e = a.DB.SaveRecord(r.Context(), rec)
	if e != nil {
		fail(w, 409, "conflict", "目标已更新，请重试")
		return
	}
	a.audit(r.Context(), current(r), "reality.target.review", rec.ID, map[string]any{"approved": in.Approve})
	respond(w, 200, map[string]any{"row": realityPoolRow(rec, allowed)})
}
func (a *App) realityPoolUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 {
		fail(w, 400, "invalid_name", "请填写200字符以内的名称")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), realityPoolCollection, r.PathValue("id"))
	if e != nil {
		fail(w, 404, "not_found", "目标不存在")
		return
	}
	allowed, _, _ := a.realityAllowed(r.Context())
	rec.Data["enabled"] = in.Enabled
	if in.Enabled && !realityAvailable(rec, allowed) {
		fail(w, 400, "review_required", "只能启用允许列表中已探测并获批准的目标")
		return
	}
	rec.Data["name"] = strings.TrimSpace(in.Name)
	rec, e = a.DB.SaveRecord(r.Context(), rec)
	if e != nil {
		fail(w, 409, "conflict", "目标已更新，请重试")
		return
	}
	a.audit(r.Context(), current(r), "reality.target.update", rec.ID, nil)
	respond(w, 200, map[string]any{"row": realityPoolRow(rec, allowed)})
}
func (a *App) realityPoolDelete(w http.ResponseWriter, r *http.Request) {
	if e := a.DB.DeleteRecord(r.Context(), realityPoolCollection, r.PathValue("id")); e != nil {
		fail(w, 404, "not_found", "目标不存在")
		return
	}
	a.audit(r.Context(), current(r), "reality.target.delete", r.PathValue("id"), nil)
	respond(w, 200, map[string]bool{"success": true})
}
