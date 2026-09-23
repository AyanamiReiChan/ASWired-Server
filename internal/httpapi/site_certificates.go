package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/AyanamiReiChan/ASWired-Server/internal/sitecert"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) siteCertificateTargets() []sitecert.Target {
	return []sitecert.Target{{ID: "panel", Name: "主控网站", URL: a.Config.PublicURL}, {ID: "komari", Name: "Komari", URL: a.Config.KomariPublicURL}}
}

func (a *App) externalSiteHTTPS(ctx context.Context) (bool, error) {
	row, err := a.DB.GetRecord(ctx, "_siteCertificateSettings", "current")
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return boolean(row.Data, "externalHTTPS"), nil
}

func (a *App) siteCertificates(w http.ResponseWriter, r *http.Request) {
	external, err := a.externalSiteHTTPS(r.Context())
	if err != nil {
		fail(w, 500, "store_failed", "无法读取网站证书设置")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, map[string]any{"sites": a.siteInspector.Check(r.Context(), a.siteCertificateTargets()), "externalHTTPS": external, "deployment": a.siteCertificateClient.Status(r.Context()), "bindings": a.siteCertificateClient.Bindings()})
}

func (a *App) configureSiteCertificates(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ExternalHTTPS *bool `json:"externalHTTPS"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.ExternalHTTPS == nil {
		fail(w, 400, "invalid_request", "请指定外部 HTTPS 管理模式")
		return
	}
	a.siteCertificateMu.Lock()
	defer a.siteCertificateMu.Unlock()
	status := a.siteCertificateClient.Status(r.Context())
	if status.Phase == "queued" || status.Phase == "applying" {
		fail(w, 409, "operation_pending", "网站证书操作尚未完成")
		return
	}
	if !*input.ExternalHTTPS && !status.Supported {
		fail(w, 400, "unsupported", status.Reason)
		return
	}
	sites := []string{}
	for _, target := range a.siteCertificateTargets() {
		if _, ok := a.siteCertificateClient.Bindings()[target.ID]; ok {
			sites = append(sites, target.ID)
		}
	}
	if *input.ExternalHTTPS && len(sites) > 0 {
		if err := a.siteCertificateClient.Enqueue(r.Context(), sitecert.Request{ID: newID(), Operation: "external", Sites: sites}); err != nil {
			fail(w, 400, "deployment_failed", err.Error())
			return
		}
	}
	row, err := a.DB.GetRecord(r.Context(), "_siteCertificateSettings", "current")
	if errors.Is(err, store.ErrNotFound) {
		row = store.Record{Collection: "_siteCertificateSettings", ID: "current", Data: map[string]any{}}
	} else if err != nil {
		fail(w, 500, "store_failed", "无法读取网站证书设置")
		return
	}
	row.Data["externalHTTPS"] = *input.ExternalHTTPS
	_, err = a.DB.SaveRecord(r.Context(), row)
	if err != nil {
		fail(w, 500, "store_failed", "网站设置保存失败，请刷新检查部署状态")
		return
	}
	a.audit(r.Context(), current(r), "certificate.website.mode", "", map[string]any{"externalHTTPS": *input.ExternalHTTPS})
	respond(w, 200, map[string]any{"externalHTTPS": *input.ExternalHTTPS, "deployment": a.siteCertificateClient.Status(r.Context())})
}

func (a *App) validateWebsiteTargets(row map[string]any) error {
	ids := stringList(row["websiteTargets"])
	seen := map[string]bool{}
	for _, id := range ids {
		if (id != "panel" && id != "komari") || seen[id] {
			return errors.New("网站部署目标仅支持主控网站和 Komari，且不能重复")
		}
		seen[id] = true
		for _, target := range a.siteCertificateTargets() {
			if target.ID == id {
				u, err := url.Parse(target.URL)
				if err != nil || u.Scheme != "https" || u.Hostname() == "" {
					return errors.New("请先为所选网站配置 HTTPS 公网地址")
				}
			}
		}
	}
	return nil
}

func (a *App) deployWebsiteCertificate(ctx context.Context, asset, material store.Record, sites []string) (sitecert.Deployment, error) {
	a.siteCertificateMu.Lock()
	defer a.siteCertificateMu.Unlock()
	if err := a.validateWebsiteTargets(map[string]any{"websiteTargets": sites}); err != nil {
		return sitecert.Deployment{}, err
	}
	external, err := a.externalSiteHTTPS(ctx)
	if err != nil {
		return sitecert.Deployment{}, err
	}
	if external {
		return sitecert.Deployment{}, errors.New("网站当前由外部 HTTPS/反代管理，请先关闭外部管理模式再部署网站证书")
	}
	domains := []string{}
	for _, site := range sites {
		for _, target := range a.siteCertificateTargets() {
			if target.ID == site {
				u, _ := url.Parse(target.URL)
				domains = append(domains, u.Hostname())
			}
		}
	}
	if _, err := validateCertificatePair(text(material.Data, "certificate"), text(material.Data, "privateKey"), domains); err != nil {
		return sitecert.Deployment{}, err
	}
	request := sitecert.Request{ID: newID(), Operation: "deploy", CertificateID: asset.ID, Sites: sites, Certificate: text(material.Data, "certificate"), PrivateKey: text(material.Data, "privateKey")}
	if err := a.siteCertificateClient.Enqueue(ctx, request); err != nil {
		return sitecert.Deployment{}, err
	}
	return sitecert.Deployment{Supported: true, Phase: "queued", Message: "等待部署服务校验并切换网站证书", CertificateID: asset.ID, Serial: text(asset.Data, "serial"), Sites: sites, RequestID: request.ID}, nil
}
