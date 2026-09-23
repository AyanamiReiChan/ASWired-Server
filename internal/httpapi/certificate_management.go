package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

func (a *App) validateCertificateRecord(ctx context.Context, collection string, row map[string]any) error {
	if collection == "dnsProviders" {
		_, err := dnsChallengeProvider(row, a.client)
		return err
	}
	domains, err := certificateDomains(row)
	if err != nil {
		return err
	}
	row["domains"] = domains
	if err := a.validateWebsiteTargets(row); err != nil {
		return err
	}
	for _, id := range stringList(row["serverIds"]) {
		if _, err := a.DB.GetRecord(ctx, "servers", id); err != nil {
			return fmt.Errorf("部署服务器不存在：%s", id)
		}
	}
	if boolean(row, "autoDeploy") && len(stringList(row["serverIds"])) == 0 && len(stringList(row["websiteTargets"])) == 0 {
		return errors.New("自动部署需要选择网站或节点服务器")
	}
	manual := text(row, "type") == "manual" || text(row, "provider") == "manual"
	if manual && !boolean(row, "autoRenew") {
		return nil
	}
	if _, err := mail.ParseAddress(text(row, "email")); err != nil {
		return errors.New("请填写有效的ACME联系邮箱")
	}
	if directory := text(row, "acmeDirectory"); directory != "" {
		u, err := url.Parse(directory)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("ACME目录须为HTTPS地址")
		}
	}
	if (text(row, "eabKid") == "") != (text(row, "eabHmacKey") == "") {
		return errors.New("EAB账户ID与HMAC密钥需要同时填写")
	}
	if key := text(row, "eabHmacKey"); key != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key, "="))
		if err != nil || len(raw) < 32 {
			return errors.New("EAB密钥须为至少32字节密钥的base64url编码")
		}
	}
	switch strings.ToUpper(text(row, "challenge")) {
	case "HTTP-01", "HTTP01":
		for _, domain := range domains {
			if strings.HasPrefix(domain, "*.") {
				return errors.New("通配符证书需要DNS-01验证")
			}
		}
		if port := number(row, "httpChallengePort"); port < 1 || port > 65535 {
			return errors.New("HTTP验证监听端口须为1至65535")
		}
	case "DNS-01", "DNS01", "":
		if id := text(row, "dnsProviderId"); id != "" {
			if _, err := a.DB.GetRecord(ctx, "dnsProviders", id); err != nil {
				return errors.New("DNS提供商不存在")
			}
		} else if _, err := dnsChallengeProvider(row, a.client); err != nil {
			return err
		}
	default:
		return errors.New("验证方式仅支持DNS-01和HTTP-01")
	}
	return nil
}

func (a *App) certificateReferenceCheck(ctx context.Context, collection, id string) error {
	if collection == "certificates" {
		for _, binding := range a.siteCertificateClient.Bindings() {
			if binding.CertificateID == id {
				return errors.New("网站正在使用此证书，请先部署其他证书或交回外部 HTTPS 管理")
			}
		}
		status := a.siteCertificateClient.Status(ctx)
		if status.Phase == "queued" || status.Phase == "applying" {
			return errors.New("网站证书操作尚未完成，暂不能删除证书")
		}
	}
	dependencies := []string{"inbounds", "sites"}
	if collection == "dnsProviders" {
		dependencies = []string{"certificates", "servers"}
	}
	for _, dependent := range dependencies {
		rows, err := a.DB.ListRecords(ctx, dependent, "")
		if err != nil {
			return err
		}
		for _, row := range rows {
			used := text(row.Data, "certificateId") == id || text(row.Data, "certificate") == id
			if collection == "dnsProviders" {
				ddns, _ := row.Data["ddns"].(map[string]any)
				used = text(row.Data, "dnsProviderId") == id || text(ddns, "dnsProviderId") == id
			}
			if used {
				return fmt.Errorf("仍被 %s 引用，请先解除关联", defaultText(row.Data, "name", row.ID))
			}
		}
	}
	return nil
}
