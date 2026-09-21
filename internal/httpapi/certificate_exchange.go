package httpapi

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"sort"
	"strings"
)

func decodeCertificatePEM(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "-----BEGIN ") {
		return value + "\n", nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		raw, e := encoding.DecodeString(value)
		if e == nil && bytes.HasPrefix(bytes.TrimSpace(raw), []byte("-----BEGIN ")) {
			return string(raw), nil
		}
	}
	return "", errors.New("证书和私钥须为PEM文本或PEM的base64编码")
}

func (a *App) certificateUpload(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Domain      string `json:"domain"`
		Certificate string `json:"cert_pem"`
		Key         string `json:"key_pem"`
		Deploy      *bool  `json:"deploy"`
	}
	if !decode(w, r, &input) {
		return
	}
	domains, e := certificateDomains(map[string]any{"domains": []string{input.Domain}})
	if e != nil {
		fail(w, 400, "invalid_domain", e.Error())
		return
	}
	certificate, e := decodeCertificatePEM(input.Certificate)
	if e != nil {
		fail(w, 400, "invalid_certificate", e.Error())
		return
	}
	key, e := decodeCertificatePEM(input.Key)
	if e != nil {
		fail(w, 400, "invalid_key", e.Error())
		return
	}
	if _, e = validateCertificatePair(certificate, key, domains); e != nil {
		fail(w, 400, "invalid_certificate", e.Error())
		return
	}
	certificateMu.Lock()
	assets, e := a.DB.ListRecords(r.Context(), "certificates", "")
	if e != nil {
		certificateMu.Unlock()
		fail(w, 500, "store_failed", "无法读取证书")
		return
	}
	var asset store.Record
	for _, candidate := range assets {
		names, err := certificateDomains(candidate.Data)
		if err == nil && len(names) > 0 && names[0] == domains[0] {
			if asset.ID != "" {
				certificateMu.Unlock()
				fail(w, 409, "ambiguous_domain", "存在多个同主域名证书，请先整理重复记录")
				return
			}
			asset = candidate
		}
	}
	if asset.ID == "" {
		digest := sha256.Sum256([]byte(domains[0]))
		asset = store.Record{Collection: "certificates", ID: "manual-" + hex.EncodeToString(digest[:16]), Data: map[string]any{"name": domains[0], "domains": domains}}
	}
	asset.Data["autoRenew"] = false
	asset.Data["provider"] = "manual"
	asset.Data["type"] = "manual"
	asset, e = a.saveCertificateMaterial(r.Context(), asset, certificate, key, "manual")
	certificateMu.Unlock()
	if e != nil {
		fail(w, 400, "certificate_save_failed", e.Error())
		return
	}
	ids := map[string]bool{}
	for _, id := range stringList(asset.Data["serverIds"]) {
		ids[id] = true
	}
	for _, collection := range []string{"inbounds", "sites"} {
		refs, err := a.DB.ListRecords(r.Context(), collection, "")
		if err != nil {
			continue
		}
		for _, ref := range refs {
			if text(ref.Data, "certificateId") == asset.ID || text(ref.Data, "certificate") == asset.ID {
				if id := text(ref.Data, "serverId"); id != "" {
					ids[id] = true
				}
			}
		}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	tasks := []any{}
	deploymentErrors := []any{}
	for _, id := range ordered {
		if input.Deploy != nil && !*input.Deploy {
			break
		}
		task, err := a.queue(r.Context(), current(r), id, "certificate.deploy", map[string]any{"name": asset.ID, "certificate": certificate, "private_key": key})
		if err != nil {
			deploymentErrors = append(deploymentErrors, map[string]any{"serverId": id, "error": err.Error()})
			continue
		}
		tasks = append(tasks, taskRow(task))
	}
	a.audit(r.Context(), current(r), "certificate.upload", asset.ID, map[string]any{"domain": domains[0], "serial": asset.Data["serial"], "deploymentCount": len(tasks)})
	respond(w, 200, map[string]any{"certificate_id": asset.ID, "row": rowOf(asset, false), "deployments": tasks, "deployment_errors": deploymentErrors, "message": "证书材料已验证保存；部署是否成功请查看节点任务结果"})
}

func (a *App) certificateDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asset, e := a.DB.GetRecord(r.Context(), "certificates", id)
	if e != nil {
		fail(w, 404, "not_found", "证书不存在")
		return
	}
	material, e := a.DB.GetRecord(r.Context(), "_certificateMaterial", id)
	if e != nil {
		fail(w, 404, "material_missing", "证书尚无可下载材料")
		return
	}
	var body bytes.Buffer
	archive := zip.NewWriter(&body)
	for _, item := range []struct{ Name, Value string }{{"fullchain.pem", text(material.Data, "certificate")}, {"privkey.pem", text(material.Data, "privateKey")}} {
		header := &zip.FileHeader{Name: item.Name, Method: zip.Deflate}
		header.SetMode(0600)
		file, err := archive.CreateHeader(header)
		if err != nil {
			fail(w, 500, "archive_failed", "打包失败")
			return
		}
		if _, err = file.Write([]byte(item.Value)); err != nil {
			fail(w, 500, "archive_failed", "打包失败")
			return
		}
	}
	if e = archive.Close(); e != nil {
		fail(w, 500, "archive_failed", "打包失败")
		return
	}
	a.audit(r.Context(), current(r), "certificate.download", id, map[string]any{"serial": asset.Data["serial"]})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="certificate.zip"`)
	w.Write(body.Bytes())
}
