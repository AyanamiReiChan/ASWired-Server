package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) registerFederation(mux *http.ServeMux) {
	a.registerFederationAgent(mux)
	mux.HandleFunc("POST /api/auth/callback/authorize", a.withUser(a.callbackAuthorize))
	mux.HandleFunc("POST /api/auth/callback/exchange", a.callbackExchange)
	mux.HandleFunc("GET /api/federation/shares/{id}/nodes", a.federationFeed)
}

func hashOpaque(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func secureOrigin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("需要有效HTTPS地址")
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("只有本机开发地址允许HTTP")
		}
	}
	return u.Scheme + "://" + u.Host, nil
}
func (a *App) callbackURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Fragment != "" {
		return nil, errors.New("回接地址无效")
	}
	origin, e := secureOrigin(raw)
	if e != nil {
		return nil, e
	}
	allowed := append(append([]string{}, a.Config.AllowedOrigins...), a.Config.PublicURL)
	for _, v := range allowed {
		configured, e := secureOrigin(v)
		if e == nil && origin == configured {
			return u, nil
		}
	}
	return nil, errors.New("回接来源未列入主控允许的网站来源")
}
func validPKCEVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func (a *App) callbackAuthorize(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RedirectURI string `json:"redirect_uri"`
		Challenge   string `json:"code_challenge"`
		Method      string `json:"code_challenge_method"`
		State       string `json:"state"`
	}
	if !decode(w, r, &in) {
		return
	}
	u, e := a.callbackURL(in.RedirectURI)
	if e != nil {
		fail(w, 400, "invalid_callback", e.Error())
		return
	}
	challenge, e := base64.RawURLEncoding.DecodeString(in.Challenge)
	if e != nil || len(challenge) != 32 || in.Method != "S256" || len(in.State) < 16 || len(in.State) > 256 {
		fail(w, 400, "invalid_pkce", "回接必须提供S256 challenge和随机state")
		return
	}
	user := current(r)
	code := newID() + newID()
	_, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_loginCallbacks", ID: hashOpaque(code), OwnerID: user.ID, Data: map[string]any{"redirect_uri": in.RedirectURI, "challenge": in.Challenge, "token_version": user.TokenVersion, "expires_at": time.Now().Add(2 * time.Minute).Unix()}})
	if e != nil {
		fail(w, 500, "callback_failed", "无法建立登录回接")
		return
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", in.State)
	u.RawQuery = q.Encode()
	respond(w, 200, map[string]any{"redirect_url": u.String(), "expires_in": 120})
}

func (a *App) callbackExchange(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁")
		return
	}
	var in struct {
		Code        string `json:"code"`
		Verifier    string `json:"code_verifier"`
		RedirectURI string `json:"redirect_uri"`
	}
	if !decode(w, r, &in) {
		return
	}
	callback, e := a.callbackURL(in.RedirectURI)
	if e != nil || !validPKCEVerifier(in.Verifier) || len(in.Code) > 128 {
		fail(w, 400, "invalid_callback", "回接请求无效")
		return
	}
	origin := callback.Scheme + "://" + callback.Host
	if r.Header.Get("Origin") != origin {
		fail(w, 403, "origin_denied", "回接兑换必须来自绑定的网站来源")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), "_loginCallbacks", hashOpaque(in.Code))
	if e != nil {
		fail(w, 401, "invalid_code", "登录回接已过期或已使用")
		return
	}
	sum := sha256.Sum256([]byte(in.Verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if text(rec.Data, "redirect_uri") != in.RedirectURI || !constant(text(rec.Data, "challenge"), challenge) || number(rec.Data, "expires_at") <= float64(time.Now().Unix()) {
		fail(w, 401, "invalid_code", "登录回接验证失败")
		return
	}
	u, e := a.DB.UserByID(r.Context(), rec.OwnerID)
	if e != nil || u.Disabled || int64(number(rec.Data, "token_version")) != u.TokenVersion {
		fail(w, 401, "session_expired", "原登录状态已失效")
		return
	}
	deleted, e := a.DB.DB().ExecContext(r.Context(), a.DB.Bind(`DELETE FROM records WHERE collection=? AND id=? AND version=?`), rec.Collection, rec.ID, rec.Version)
	if e != nil {
		fail(w, 500, "callback_failed", "回接兑换失败")
		return
	}
	count, e := deleted.RowsAffected()
	if e != nil || count != 1 {
		fail(w, 401, "invalid_code", "登录回接已使用")
		return
	}
	a.issue(w, u)
}

type federationNode struct {
	ID   string         `json:"id"`
	Node map[string]any `json:"node"`
}
type federationPayload struct {
	Protocol    string           `json:"protocol"`
	ShareID     string           `json:"share_id"`
	GeneratedAt int64            `json:"generated_at"`
	ExpiresAt   int64            `json:"expires_at"`
	Nodes       []federationNode `json:"nodes"`
	Skipped     int              `json:"skipped,omitempty"`
}

const federationProtocol = "aswired-node-share-v1"

var sharedNodeFields = []string{"name", "protocol", "host", "server", "port", "uuid", "password", "username", "cipher", "security", "sni", "publicKey", "shortId", "flow", "fingerprint", "network", "path", "serviceName", "uri", "type", "tls", "servername", "client-fingerprint", "reality-opts", "ws-opts", "grpc-opts", "skip-cert-verify", "udp", "alterId", "alpn"}

func sharedNodeProjection(node map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range sharedNodeFields {
		if value, ok := node[key]; ok {
			out[key] = value
		}
	}
	return out
}
func federationStringList(raw any) ([]string, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("需要显式标识数组")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, v := range list {
		s, ok := v.(string)
		if !ok || s == "" || len(s) > 200 || seen[s] {
			return nil, errors.New("标识数组包含无效或重复项目")
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

func (a *App) federationAction(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	if strings.HasPrefix(in.Action, "federation.agent.") {
		return a.federationAgentAction(ctx, u, in)
	}
	if u.Role != "admin" {
		return nil, errors.New("需要管理员权限")
	}
	p := in.Params
	if p == nil {
		p = map[string]any{}
	}
	switch in.Action {
	case "federation.publish":
		ids, e := federationStringList(p["nodeIds"])
		if e != nil || len(ids) == 0 || len(ids) > 1000 {
			return nil, errors.New("请选择1至1000个要分享的节点")
		}
		for _, id := range ids {
			node, err := a.DB.GetRecord(ctx, "nodes", id)
			if err != nil {
				return nil, err
			}
			if _, err := normalizedRealityNode(node.Data, true); err != nil {
				return nil, err
			}
		}
		id := in.TargetID
		if id == "" {
			id = newID()
		}
		if strings.ContainsAny(id, "/\\\x00") {
			return nil, errors.New("分享标识无效")
		}
		previous, e := a.DB.GetRecord(ctx, "_federationShares", id)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
		token := newID() + newID()
		expires := int64(number(p, "expiresAt"))
		if expires > 0 && expires <= time.Now().Unix() {
			return nil, errors.New("分享到期时间必须在未来")
		}
		name := text(p, "name")
		if name == "" {
			name = "节点分享"
		}
		_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_federationShares", ID: id, OwnerID: u.ID, Version: previous.Version, Data: map[string]any{"name": name, "node_ids": ids, "token_hash": hashOpaque(token), "enabled": true, "expires_at": expires}})
		if e != nil {
			return nil, e
		}
		if e = a.federationView(ctx, id, map[string]any{"name": name, "direction": "owner", "status": "已发布", "scope": "selected_nodes", "nodes": len(ids), "protocol": federationProtocol}); e != nil {
			return nil, e
		}
		return map[string]any{"id": id, "token": token, "owner_url": a.Config.PublicURL, "share_id": id, "scope": "selected_nodes", "message": "令牌仅本次显示；重新发布会立即替换旧令牌"}, nil
	case "federation.revoke":
		rec, e := a.DB.GetRecord(ctx, "_federationShares", in.TargetID)
		if e != nil {
			return nil, e
		}
		rec.Data["enabled"] = false
		if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
			return nil, e
		}
		_ = a.federationView(ctx, rec.ID, map[string]any{"name": text(rec.Data, "name"), "direction": "owner", "status": "已撤销", "scope": "selected_nodes"})
		return map[string]any{"success": true, "existing_agent_resources_removed": false}, nil
	case "federation.connect":
		base := strings.TrimRight(text(p, "ownerUrl"), "/")
		parsed, e := url.Parse(base)
		if _, err := secureOrigin(base); err != nil || e != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return nil, errors.New("拥有方地址须为HTTPS主控来源，本机测试可用HTTP")
		}
		shareID := text(p, "shareId")
		token := text(p, "token")
		if shareID == "" || strings.ContainsAny(shareID, "/\\\x00") || len(token) < 24 {
			return nil, errors.New("缺少有效分享标识或分享令牌")
		}
		id := in.TargetID
		if id == "" {
			id = newID()
		}
		prior, e := a.DB.GetRecord(ctx, "_federationPeers", id)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
		name := text(p, "name")
		if name == "" {
			name = "联邦节点来源"
		}
		rec, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_federationPeers", ID: id, OwnerID: u.ID, Version: prior.Version, Data: map[string]any{"name": name, "owner_url": base, "share_id": shareID, "token": token, "enabled": true}})
		if e != nil {
			return nil, e
		}
		return a.pullFederation(ctx, rec)
	case "federation.sync":
		rec, e := a.DB.GetRecord(ctx, "_federationPeers", in.TargetID)
		if e != nil {
			return nil, e
		}
		return a.pullFederation(ctx, rec)
	case "federation.disconnect":
		rec, e := a.DB.GetRecord(ctx, "_federationPeers", in.TargetID)
		if e != nil {
			return nil, e
		}
		rec.Data["enabled"] = false
		delete(rec.Data, "token")
		if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
			return nil, e
		}
		a.markFederationStale(ctx, rec, "已断开（缓存）")
		return map[string]any{"success": true, "cached_nodes_retained": true}, nil
	default:
		return nil, errors.New("不支持的联邦操作")
	}
}

func (a *App) federationView(ctx context.Context, id string, data map[string]any) error {
	old, e := a.DB.GetRecord(ctx, "shares", id)
	if e != nil && !errors.Is(e, store.ErrNotFound) {
		return e
	}
	_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "shares", ID: id, Data: data, Version: old.Version})
	return e
}
func (a *App) federationFeed(w http.ResponseWriter, r *http.Request) {
	rec, e := a.DB.GetRecord(r.Context(), "_federationShares", r.PathValue("id"))
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		fail(w, 401, "share_denied", "分享凭据无效")
		return
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if e != nil || !boolean(rec.Data, "enabled") || !constant(text(rec.Data, "token_hash"), hashOpaque(token)) || (number(rec.Data, "expires_at") > 0 && number(rec.Data, "expires_at") <= float64(time.Now().Unix())) {
		fail(w, 401, "share_denied", "分享已失效或凭据无效")
		return
	}
	ids, e := federationStringList(rec.Data["node_ids"])
	if e != nil {
		fail(w, 500, "share_invalid", "分享范围损坏")
		return
	}
	now := time.Now()
	payload := federationPayload{Protocol: federationProtocol, ShareID: rec.ID, GeneratedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(), Nodes: []federationNode{}}
	for _, id := range ids {
		node, e := a.DB.GetRecord(r.Context(), "nodes", id)
		if e != nil {
			continue
		}
		normalized, err := normalizedRealityNode(node.Data, true)
		if err != nil || disabledStatus(node.Data) {
			payload.Skipped++
			continue
		}
		payload.Nodes = append(payload.Nodes, federationNode{ID: id, Node: sharedNodeProjection(normalized)})
	}
	respond(w, 200, payload)
}

func (a *App) pullFederation(ctx context.Context, peer store.Record) (result map[string]any, err error) {
	if !boolean(peer.Data, "enabled") {
		return nil, errors.New("联邦来源已停用")
	}
	defer func() {
		if err != nil {
			a.markFederationStale(ctx, peer, "来源失联（缓存）")
		}
	}()
	base := text(peer.Data, "owner_url")
	if _, err = secureOrigin(base); err != nil {
		return nil, err
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/federation/shares/"+url.PathEscape(text(peer.Data, "share_id"))+"/nodes", nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+text(peer.Data, "token"))
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("联邦地址不能重定向") }}
	response, e := client.Do(req)
	if e != nil {
		return nil, errors.New("无法连接联邦来源")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("联邦来源返回HTTP %d", response.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if e != nil || len(body) > 8<<20 {
		return nil, errors.New("联邦节点响应过大或无法读取")
	}
	var payload federationPayload
	if e = json.Unmarshal(body, &payload); e != nil {
		return nil, e
	}
	now := time.Now().Unix()
	if payload.Protocol != federationProtocol || payload.ShareID != text(peer.Data, "share_id") || payload.ExpiresAt <= now || payload.ExpiresAt > now+3600 || payload.GeneratedAt > now+90 || len(payload.Nodes) > 1000 {
		return nil, errors.New("联邦来源版本或有效期不正确")
	}
	seen := map[string]bool{}
	for _, n := range payload.Nodes {
		if n.ID == "" || seen[n.ID] || n.Node == nil {
			return nil, errors.New("联邦节点标识重复或无效")
		}
		seen[n.ID] = true
	}
	currentNodes, e := a.DB.ListRecords(ctx, "nodes", "")
	if e != nil {
		return nil, e
	}
	previous := map[string]store.Record{}
	for _, node := range currentNodes {
		if text(node.Data, "federationPeerId") == peer.ID {
			previous[text(node.Data, "federationRemoteId")] = node
		}
	}
	accepted, skipped := 0, payload.Skipped
	for _, n := range payload.Nodes {
		old := previous[n.ID]
		data, err := normalizedRealityNode(sharedNodeProjection(n.Node), true)
		if err != nil {
			skipped++
			continue
		}
		accepted++
		remoteName := text(data, "name")
		if old.ID != "" && text(old.Data, "name") != text(old.Data, "federationRemoteName") {
			data["name"] = old.Data["name"]
		}
		data["federationRemoteName"] = remoteName
		data["federationPeerId"] = peer.ID
		data["federationRemoteId"] = n.ID
		data["federationExpiresAt"] = payload.ExpiresAt
		data["federationStale"] = false
		data["source"] = "联邦 · " + text(peer.Data, "name")
		data["status"] = "待测试"
		id := old.ID
		if id == "" {
			id = "fed-" + hashOpaque(peer.ID + "/" + n.ID)[:24]
		}
		if _, e = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: id, Data: data, Version: old.Version}); e != nil {
			return nil, e
		}
	}
	for remoteID, old := range previous {
		if !seen[remoteID] {
			old.Data["federationStale"] = true
			old.Data["enabled"] = false
			old.Data["status"] = "分享已撤回"
			if _, e = a.DB.SaveRecord(ctx, old); e != nil {
				return nil, e
			}
		}
	}
	peer.Data["last_sync"] = now
	peer.Data["expires_at"] = payload.ExpiresAt
	peer.Data["last_error"] = ""
	if _, e = a.DB.SaveRecord(ctx, peer); e != nil {
		return nil, e
	}
	if e = a.federationView(ctx, peer.ID, map[string]any{"name": text(peer.Data, "name"), "direction": "consumer", "ownerUrl": base, "status": "已同步", "scope": "selected_nodes", "nodes": accepted, "skipped": skipped, "expiresAt": payload.ExpiresAt}); e != nil {
		return nil, e
	}
	return map[string]any{"success": true, "id": peer.ID, "nodes": accepted, "skipped": skipped, "expires_at": payload.ExpiresAt, "scope": "selected_nodes"}, nil
}

func (a *App) markFederationStale(ctx context.Context, peer store.Record, status string) {
	nodes, e := a.DB.ListRecords(ctx, "nodes", "")
	if e == nil {
		for _, node := range nodes {
			if text(node.Data, "federationPeerId") == peer.ID {
				node.Data["federationStale"] = true
				node.Data["status"] = status
				_, _ = a.DB.SaveRecord(ctx, node)
			}
		}
	}
	_ = a.federationView(ctx, peer.ID, map[string]any{"name": text(peer.Data, "name"), "direction": "consumer", "ownerUrl": text(peer.Data, "owner_url"), "status": status, "scope": "selected_nodes", "stale": true})
}
func (a *App) refreshFederations(ctx context.Context) {
	peers, e := a.DB.ListRecords(ctx, "_federationPeers", "")
	if e != nil {
		return
	}
	for _, peer := range peers {
		if boolean(peer.Data, "enabled") && number(peer.Data, "last_sync") < float64(time.Now().Add(-5*time.Minute).Unix()) {
			_, _ = a.pullFederation(ctx, peer)
		}
	}
}
