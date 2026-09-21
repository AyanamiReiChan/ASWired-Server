package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

const generatedSubscriptionCollection = "_generatedSubscriptions"

type generatorCategory struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Policy      string   `json:"policy"`
	Rules       []string `json:"rules"`
	Recommended bool     `json:"recommended"`
}

// Bundled rules avoid background downloads on the controller and Agents.
var generatorCategories = []generatorCategory{
	{"ads", "广告拦截", "REJECT", []string{"DOMAIN-SUFFIX,doubleclick.net", "DOMAIN-SUFFIX,googlesyndication.com", "DOMAIN-SUFFIX,adservice.google.com"}, false},
	{"private", "私有网络", "DIRECT", []string{"DOMAIN-SUFFIX,local", "DOMAIN-SUFFIX,lan", "IP-CIDR,10.0.0.0/8", "IP-CIDR,172.16.0.0/12", "IP-CIDR,192.168.0.0/16", "IP-CIDR,127.0.0.0/8", "IP-CIDR6,fc00::/7", "IP-CIDR6,fe80::/10"}, true},
	{"ai", "AI 服务", "ASWired", []string{"DOMAIN-SUFFIX,openai.com", "DOMAIN-SUFFIX,chatgpt.com", "DOMAIN-SUFFIX,oaistatic.com", "DOMAIN-SUFFIX,oaiusercontent.com", "DOMAIN-SUFFIX,anthropic.com", "DOMAIN-SUFFIX,claude.ai", "DOMAIN-SUFFIX,perplexity.ai", "DOMAIN,gemini.google.com"}, true},
	{"youtube", "YouTube", "ASWired", []string{"DOMAIN-SUFFIX,youtube.com", "DOMAIN-SUFFIX,youtu.be", "DOMAIN-SUFFIX,googlevideo.com", "DOMAIN-SUFFIX,ytimg.com", "DOMAIN-SUFFIX,youtubei.googleapis.com"}, true},
	{"google", "谷歌服务", "ASWired", []string{"DOMAIN-SUFFIX,google.com", "DOMAIN-SUFFIX,googleapis.com", "DOMAIN-SUFFIX,gstatic.com", "DOMAIN-SUFFIX,googleusercontent.com", "DOMAIN-SUFFIX,google.co.jp", "DOMAIN-SUFFIX,google.com.hk"}, true},
	{"telegram", "电报消息", "ASWired", []string{"DOMAIN-SUFFIX,telegram.org", "DOMAIN-SUFFIX,t.me", "DOMAIN-SUFFIX,telegram.me", "DOMAIN-SUFFIX,telegra.ph", "IP-CIDR,149.154.160.0/20", "IP-CIDR,91.108.4.0/22", "IP-CIDR,91.108.8.0/22", "IP-CIDR,91.108.12.0/22", "IP-CIDR,91.108.16.0/22", "IP-CIDR,91.108.56.0/22"}, true},
	{"github", "GitHub", "ASWired", []string{"DOMAIN-SUFFIX,github.com", "DOMAIN-SUFFIX,githubusercontent.com", "DOMAIN-SUFFIX,githubassets.com", "DOMAIN-SUFFIX,github.io"}, true},
	{"bilibili", "哔哩哔哩", "DIRECT", []string{"DOMAIN-SUFFIX,bilibili.com", "DOMAIN-SUFFIX,bilivideo.com", "DOMAIN-SUFFIX,hdslb.com", "DOMAIN-SUFFIX,b23.tv"}, false},
	{"microsoft", "微软服务", "ASWired", []string{"DOMAIN-SUFFIX,microsoft.com", "DOMAIN-SUFFIX,live.com", "DOMAIN-SUFFIX,office.com", "DOMAIN-SUFFIX,office365.com", "DOMAIN-SUFFIX,outlook.com", "DOMAIN-SUFFIX,onedrive.com", "DOMAIN-SUFFIX,bing.com"}, false},
	{"apple", "苹果服务", "DIRECT", []string{"DOMAIN-SUFFIX,apple.com", "DOMAIN-SUFFIX,icloud.com", "DOMAIN-SUFFIX,icloud-content.com", "DOMAIN-SUFFIX,mzstatic.com"}, false},
	{"streaming", "流媒体", "ASWired", []string{"DOMAIN-SUFFIX,netflix.com", "DOMAIN-SUFFIX,nflxvideo.net", "DOMAIN-SUFFIX,nflximg.net", "DOMAIN-SUFFIX,disneyplus.com", "DOMAIN-SUFFIX,dssott.com", "DOMAIN-SUFFIX,primevideo.com", "DOMAIN-SUFFIX,twitch.tv", "DOMAIN-SUFFIX,ttvnw.net"}, false},
	{"social", "社交媒体", "ASWired", []string{"DOMAIN-SUFFIX,x.com", "DOMAIN-SUFFIX,twitter.com", "DOMAIN-SUFFIX,twimg.com", "DOMAIN-SUFFIX,facebook.com", "DOMAIN-SUFFIX,fbcdn.net", "DOMAIN-SUFFIX,instagram.com", "DOMAIN-SUFFIX,reddit.com", "DOMAIN-SUFFIX,discord.com", "DOMAIN-SUFFIX,discordapp.net"}, false},
	{"games", "游戏平台", "ASWired", []string{"DOMAIN-SUFFIX,steampowered.com", "DOMAIN-SUFFIX,steamcommunity.com", "DOMAIN-SUFFIX,steamstatic.com", "DOMAIN-SUFFIX,epicgames.com", "DOMAIN-SUFFIX,playstation.com", "DOMAIN-SUFFIX,nintendo.com"}, false},
	{"spotify", "Spotify", "ASWired", []string{"DOMAIN-SUFFIX,spotify.com", "DOMAIN-SUFFIX,scdn.co", "DOMAIN-SUFFIX,spotifycdn.com"}, false},
	{"tiktok", "TikTok", "ASWired", []string{"DOMAIN-SUFFIX,tiktok.com", "DOMAIN-SUFFIX,tiktokcdn.com", "DOMAIN-SUFFIX,tiktokv.com"}, false},
	{"pixiv", "Pixiv", "ASWired", []string{"DOMAIN-SUFFIX,pixiv.net", "DOMAIN-SUFFIX,pximg.net"}, false},
	{"china", "国内服务", "DIRECT", []string{"DOMAIN-SUFFIX,cn", "DOMAIN-SUFFIX,baidu.com", "DOMAIN-SUFFIX,qq.com", "DOMAIN-SUFFIX,taobao.com", "DOMAIN-SUFFIX,tmall.com", "DOMAIN-SUFFIX,jd.com", "DOMAIN-SUFFIX,163.com", "DOMAIN-SUFFIX,alipay.com", "GEOIP,CN"}, true},
}

type generatorInput struct {
	Name           string   `json:"name"`
	NodeIDs        []string `json:"nodeIds"`
	SubscriptionID string   `json:"subscriptionId"`
	Format         string   `json:"format"`
	Mode           string   `json:"mode"`
	TemplateID     string   `json:"templateId"`
	Categories     []string `json:"categories"`
	ExpiresInDays  int      `json:"expiresInDays"`
	CreateLink     bool     `json:"createLink"`
}

func (a *App) registerSubscriptionGenerator(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/subscription-generator", a.withAdmin(a.generatorOptions))
	mux.HandleFunc("POST /api/subscription-generator", a.withAdmin(a.generatorCreate))
	mux.HandleFunc("DELETE /api/subscription-generator/{id}", a.withAdmin(a.generatorRevoke))
	mux.HandleFunc("GET /api/generated-subscriptions", a.withAdmin(a.generatedList))
	mux.HandleFunc("GET /api/generated-subscriptions/{id}", a.withAdmin(a.generatedDetail))
	mux.HandleFunc("PUT /api/generated-subscriptions/{id}", a.withAdmin(a.generatedUpdate))
	mux.HandleFunc("DELETE /api/generated-subscriptions/{id}", a.withAdmin(a.generatedDelete))
	mux.HandleFunc("POST /api/generated-subscriptions/order", a.withAdmin(a.generatedOrder))
	mux.HandleFunc("GET /api/generated-subscribe", a.generatorDownload)
}

func (a *App) generatorCandidates(ctx context.Context, actor store.User, subscriptionID, ip string) (store.Record, []store.Record, error) {
	if subscriptionID != "" {
		sub, err := a.DB.GetRecord(ctx, "subscriptions", subscriptionID)
		if err != nil {
			return sub, nil, errors.New("套餐实例不存在")
		}
		if !membershipIPAllowed(sub, ip) {
			return sub, nil, errors.New("当前地址不在套餐白名单内")
		}
		nodes, err := a.subscriptionCandidates(ctx, sub)
		return sub, nodes, err
	}
	records, err := a.DB.ListRecords(ctx, "nodes", "")
	if err != nil {
		return store.Record{}, nil, err
	}
	nodes := []store.Record{}
	for _, node := range records {
		if disabledStatus(node.Data) || boolean(node.Data, "managedInbound") || text(node.Data, "inboundId") != "" || node.OwnerID != "" && node.OwnerID != actor.ID {
			continue
		}
		if sourceID := text(node.Data, "sourceId"); sourceID != "" {
			source, err := a.DB.GetRecord(ctx, "sources", sourceID)
			if err != nil || disabledStatus(source.Data) || source.OwnerID != "" && source.OwnerID != actor.ID {
				continue
			}
		}
		nodes = append(nodes, node)
	}
	return store.Record{OwnerID: actor.ID, Data: map[string]any{}}, nodes, nil
}

func generatedLinkRow(rec store.Record) map[string]any {
	return map[string]any{"id": rec.ID, "name": rec.Data["name"], "format": rec.Data["format"], "createdAt": rec.CreatedAt, "expiresAt": rec.Data["expiresAt"], "nodeCount": len(stringList(rec.Data["nodeIds"])), "revoked": boolean(rec.Data, "revoked")}
}

func (a *App) generatorOptions(w http.ResponseWriter, r *http.Request) {
	sub, nodes, err := a.generatorCandidates(r.Context(), current(r), r.URL.Query().Get("subscriptionId"), requestIP(r))
	if err != nil {
		fail(w, 422, "invalid_source", err.Error())
		return
	}
	rows := []any{}
	for _, node := range nodes {
		row := map[string]any{"id": node.ID, "name": node.Data["name"], "protocol": node.Data["protocol"], "host": node.Data["host"], "port": node.Data["port"], "tags": node.Data["tags"], "region": node.Data["region"], "source": node.Data["source"]}
		formats := []string{}
		client, err := a.realitySubscriptionNode(r.Context(), node, sub)
		if err == nil {
			for _, format := range []string{"clash", "surge", "loon"} {
				if compatible(client, format) {
					formats = append(formats, format)
				}
			}
		} else {
			row["error"] = "节点配置不可用"
		}
		row["formats"] = formats
		rows = append(rows, row)
	}
	links, err := a.DB.ListRecords(r.Context(), generatedSubscriptionCollection, current(r).ID)
	if err != nil {
		fail(w, 500, "storage_error", "读取生成记录失败")
		return
	}
	recent := []any{}
	for i := len(links) - 1; i >= 0; i-- {
		recent = append(recent, generatedLinkRow(links[i]))
	}
	respond(w, 200, map[string]any{"nodes": rows, "categories": generatorCategories, "links": recent})
}

func (a *App) renderGenerated(ctx context.Context, actor store.User, in generatorInput, ip, parentHash string) (string, string, int, store.Record, error) {
	if in.Format != "clash" && in.Format != "surge" && in.Format != "loon" {
		return "", "", 0, store.Record{}, errors.New("格式仅支持 Clash、Surge、Loon")
	}
	if len(in.NodeIDs) == 0 || len(in.NodeIDs) > 500 {
		return "", "", 0, store.Record{}, errors.New("请选择 1 至 500 个节点")
	}
	if in.Mode != "custom" && in.Mode != "template" {
		return "", "", 0, store.Record{}, errors.New("规则模式无效")
	}
	sub, candidates, err := a.generatorCandidates(ctx, actor, in.SubscriptionID, ip)
	if err != nil {
		return "", "", 0, sub, err
	}
	if parentHash != "" && !constant(parentHash, hashOpaque(text(sub.Data, "token"))) {
		return "", "", 0, sub, errors.New("原套餐凭据已轮换")
	}
	byID := map[string]store.Record{}
	for _, node := range candidates {
		byID[node.ID] = node
	}
	nodes := []clientNode{}
	seen, names := map[string]bool{}, map[string]bool{"ASWired": true, "DIRECT": true, "REJECT": true, "REJECT-DROP": true}
	for _, id := range in.NodeIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		node, ok := byID[id]
		if !ok {
			return "", "", 0, sub, errors.New("所选节点已失效或不在当前授权范围内")
		}
		client, err := a.realitySubscriptionNode(ctx, node, sub)
		if err != nil {
			return "", "", 0, sub, fmt.Errorf("%s: %w", text(node.Data, "name"), err)
		}
		if !compatible(client, in.Format) {
			return "", "", 0, sub, fmt.Errorf("%s: %s", client.Name, incompatibilityReason(client, in.Format))
		}
		base := client.Name
		for suffix := 2; names[client.Name]; suffix++ {
			client.Name = fmt.Sprintf("%s (%d)", base, suffix)
		}
		names[client.Name] = true
		nodes = append(nodes, client)
	}
	renderSub := sub
	renderSub.Data = clone(sub.Data)
	delete(renderSub.Data, "scriptId")
	delete(renderSub.Data, "templateId")
	renderSub.Data["skipTemplates"] = true
	renderSub.Data["skipRuleOverrides"] = in.Mode == "custom"
	if in.Mode == "template" {
		template, err := a.DB.GetRecord(ctx, "policies", in.TemplateID)
		if err != nil || !templateMatches(template.Data, in.Format) {
			return "", "", 0, sub, errors.New("请选择与客户端匹配的模板")
		}
		renderSub.Data["skipTemplates"] = false
		renderSub.Data["templateId"] = template.ID
	}
	output, mime, _, err := a.renderClientNodes(ctx, renderSub, nodes, nil, in.Format)
	if err != nil {
		return "", "", 0, sub, err
	}
	if in.Mode == "custom" {
		selected := map[string]bool{}
		for _, id := range in.Categories {
			selected[id] = true
		}
		rules := []string{}
		for _, category := range generatorCategories {
			if !selected[category.ID] {
				continue
			}
			delete(selected, category.ID)
			for _, rule := range category.Rules {
				rule += "," + category.Policy
				if strings.HasPrefix(rule, "IP-CIDR") || strings.HasPrefix(rule, "GEOIP") {
					rule += ",no-resolve"
				}
				rules = append(rules, rule)
			}
		}
		if len(selected) > 0 {
			return "", "", 0, sub, errors.New("存在未知规则类别")
		}
		if in.Format == "clash" {
			var cfg map[string]any
			if err = yaml.Unmarshal([]byte(output), &cfg); err != nil {
				return "", "", 0, sub, err
			}
			cfg["rules"] = append(rules, "MATCH,ASWired")
			raw, err := yaml.Marshal(cfg)
			if err != nil {
				return "", "", 0, sub, err
			}
			output = string(raw)
		} else {
			// Native base output is generated locally and always has one Rule section.
			before, _, ok := strings.Cut(output, "[Rule]\n")
			if !ok {
				return "", "", 0, sub, errors.New("配置缺少规则章节")
			}
			output = before + "[Rule]\n" + strings.Join(append(rules, "FINAL,ASWired"), "\n") + "\n"
		}
	}
	return output, mime, len(nodes), sub, nil
}

func (a *App) generatorCreate(w http.ResponseWriter, r *http.Request) {
	templateMu.Lock()
	defer templateMu.Unlock()
	var in generatorInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) > 200 {
		fail(w, 400, "invalid_name", "名称不能超过 200 字节")
		return
	}
	if in.Name == "" {
		in.Name = "ASWired"
	}
	if in.CreateLink && (in.ExpiresInDays < 1 || in.ExpiresInDays > 90) {
		fail(w, 400, "invalid_expiry", "链接有效期须为 1 至 90 天")
		return
	}
	output, mime, count, sub, err := a.renderGenerated(r.Context(), current(r), in, requestIP(r), "")
	if err != nil {
		fail(w, 422, "invalid_config", err.Error())
		return
	}
	ext := "yaml"
	if in.Format == "surge" {
		ext = "conf"
	}
	if in.Format == "loon" {
		ext = "lcf"
	}
	result := map[string]any{"content": output, "mime": mime, "nodeCount": count, "filename": "aswired." + ext}
	if in.CreateLink {
		token := newID() + newID()
		raw, _ := json.Marshal(in)
		data := map[string]any{}
		_ = json.Unmarshal(raw, &data)
		delete(data, "createLink")
		expires := time.Now().UTC().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
		if parent := dateTime(text(sub.Data, "expires")); !parent.IsZero() && parent.Before(expires) {
			expires = parent
		}
		data["expiresAt"] = expires.Format(time.RFC3339Nano)
		data["tokenVersion"] = current(r).TokenVersion
		// Record JSON is encrypted by the store. Never include this in list projections.
		data["linkToken"] = token
		if sub.ID != "" {
			data["parentTokenHash"] = hashOpaque(text(sub.Data, "token"))
		}
		rec, err := a.DB.SaveRecord(r.Context(), store.Record{Collection: generatedSubscriptionCollection, ID: hashOpaque(token), OwnerID: current(r).ID, Data: data})
		if err != nil {
			fail(w, 500, "storage_error", "保存生成订阅失败")
			return
		}
		result["url"] = "/api/generated-subscribe?token=" + url.QueryEscape(token)
		result["row"] = generatedLinkRow(rec)
		a.audit(r.Context(), current(r), "subscription.generate", rec.ID, map[string]any{"nodeCount": count, "format": in.Format})
	}
	respond(w, 200, result)
}

func (a *App) generatorRevoke(w http.ResponseWriter, r *http.Request) {
	rec, err := a.DB.GetRecord(r.Context(), generatedSubscriptionCollection, r.PathValue("id"))
	if err != nil || rec.OwnerID != current(r).ID {
		fail(w, 404, "not_found", "生成记录不存在")
		return
	}
	rec.Data["revoked"] = true
	if _, err = a.DB.SaveRecord(r.Context(), rec); err != nil {
		fail(w, 409, "conflict", "记录已改变，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "subscription.generate.revoke", rec.ID, nil)
	respond(w, 200, map[string]any{"success": true})
}

func (a *App) generatorDownload(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if len(token) < 24 || len(token) > 200 {
		fail(w, 404, "not_found", "订阅链接不可用")
		return
	}
	rec, err := a.DB.GetRecord(r.Context(), generatedSubscriptionCollection, hashOpaque(token))
	if err != nil || boolean(rec.Data, "revoked") || !time.Now().Before(dateTime(text(rec.Data, "expiresAt"))) {
		fail(w, 404, "not_found", "订阅链接不可用")
		return
	}
	actor, err := a.DB.UserByID(r.Context(), rec.OwnerID)
	if err != nil || actor.Disabled || actor.Role != "admin" || actor.TokenVersion != int64(number(rec.Data, "tokenVersion")) {
		fail(w, 403, "inactive", "创建者权限已改变")
		return
	}
	var in generatorInput
	raw, _ := json.Marshal(rec.Data)
	if json.Unmarshal(raw, &in) != nil {
		fail(w, 500, "invalid_config", "订阅记录无效")
		return
	}
	output, mime, _, sub, err := a.renderGenerated(r.Context(), actor, in, requestIP(r), text(rec.Data, "parentTokenHash"))
	if err != nil {
		fail(w, 422, "invalid_config", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Profile-Update-Interval", "6")
	expiry := dateTime(text(rec.Data, "expiresAt"))
	if parent := dateTime(text(sub.Data, "expires")); !parent.IsZero() && parent.Before(expiry) {
		expiry = parent
	}
	if sub.ID != "" {
		_, up, down, _ := a.subscriptionUsage(r.Context(), sub)
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%.0f; download=%.0f; total=%.0f; expire=%d", up, down, number(sub.Data, "limit")*gib, expiry.Unix()))
	} else {
		w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=0; download=0; total=0; expire=%d", expiry.Unix()))
	}
	w.Header().Set("Content-Type", mime)
	_, _ = w.Write([]byte(output))
}
