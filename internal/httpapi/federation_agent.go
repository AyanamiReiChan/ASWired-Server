package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func (a *App) registerFederationAgent(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/federation/agent/{id}", a.federationAgentDescribe)
	mux.HandleFunc("POST /api/federation/agent/{id}/forward", a.federationAgentForward)
	mux.HandleFunc("GET /api/federation/agent/{id}/results/{job}", a.federationAgentResult)
}
func scopedFederationAction(action string) bool {
	switch action {
	case "status.get", "inbound.users.get", "inbound.users.sync", "stats.get":
		return true
	}
	return false
}
func (a *App) federationSigningKey(ctx context.Context) (ed25519.PrivateKey, error) {
	rec, e := a.DB.GetRecord(ctx, "_federationSigningIdentity", "owner")
	if errors.Is(e, store.ErrNotFound) {
		seed := make([]byte, ed25519.SeedSize)
		if _, e = rand.Read(seed); e != nil {
			return nil, e
		}
		rec, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_federationSigningIdentity", ID: "owner", Data: map[string]any{"seed": base64.RawURLEncoding.EncodeToString(seed)}})
		if errors.Is(e, store.ErrConflict) {
			rec, e = a.DB.GetRecord(ctx, "_federationSigningIdentity", "owner")
		}
	}
	if e != nil {
		return nil, e
	}
	seed, e := base64.RawURLEncoding.DecodeString(text(rec.Data, "seed"))
	if e != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("联邦签名身份损坏")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
func signedGrantOf(rec store.Record) (agentwire.SignedFederationGrant, error) {
	b, e := json.Marshal(rec.Data["signed_grant"])
	if e != nil {
		return agentwire.SignedFederationGrant{}, e
	}
	var s agentwire.SignedFederationGrant
	e = json.Unmarshal(b, &s)
	return s, e
}
func (a *App) federationAgentAction(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	if u.Role != "admin" {
		return nil, errors.New("需要管理员权限")
	}
	p := in.Params
	if p == nil {
		p = map[string]any{}
	}
	switch in.Action {
	case "federation.agent.publish":
		server, e := a.DB.GetRecord(ctx, "servers", in.TargetID)
		if e != nil {
			return nil, e
		}
		consumer := text(p, "consumerPublicKey")
		if _, e = agentwire.NewClient(consumer); e != nil {
			return nil, errors.New("消费者主控公钥无效")
		}
		namespace := text(p, "namespace")
		if !federationSafeName(namespace) {
			return nil, errors.New("命名空间仅允许字母、数字、连字符和下划线")
		}
		mapped, ok := p["inbounds"].(map[string]any)
		if !ok || len(mapped) == 0 {
			return nil, errors.New("需要显式入站别名白名单")
		}
		inbounds := map[string]string{}
		for alias, value := range mapped {
			tag, ok := value.(string)
			if !ok || tag == "" || !federationSafeName(alias) {
				return nil, errors.New("入站映射无效")
			}
			inbounds[alias] = tag
		}
		actions, e := federationStringList(p["actions"])
		if e != nil || len(actions) == 0 {
			return nil, errors.New("需要显式动作白名单")
		}
		for _, action := range actions {
			if !scopedFederationAction(action) {
				return nil, errors.New("不能通过联邦授予全局或宿主操作")
			}
		}
		expires := int64(number(p, "expiresAt"))
		if expires > 0 && expires <= time.Now().Unix() {
			return nil, errors.New("授权期限必须在未来")
		}
		identity, e := a.queue(ctx, u, server.ID, "federation.identity", nil)
		if e != nil {
			return nil, e
		}
		identity, e = a.waitFederationTask(ctx, identity.ID, 45*time.Second)
		if e != nil {
			return nil, e
		}
		var identityData map[string]any
		if e = json.Unmarshal(identity.Result, &identityData); e != nil {
			return nil, e
		}
		agentPublic := text(identityData, "public_key")
		if _, e = agentwire.NewClient(agentPublic); e != nil {
			return nil, errors.New("节点未提供有效联邦身份")
		}
		id := text(p, "shareId")
		if id == "" {
			id = newID()
		}
		if !federationSafeName(id) {
			return nil, errors.New("分享标识无效")
		}
		old, e := a.DB.GetRecord(ctx, "_federationAgentShares", id)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
		revision := uint64(1)
		if old.ID != "" {
			previous, e := signedGrantOf(old)
			if e != nil {
				return nil, e
			}
			revision = previous.Grant.Revision + 1
			if previous.Grant.Namespace != namespace {
				return nil, errors.New("既有分享的命名空间不可变更")
			}
		}
		grant := agentwire.FederationGrant{Protocol: agentwire.FederationProtocol, ID: id, Revision: revision, ServerID: server.ID, AgentPublicKey: agentPublic, ConsumerPublicKey: consumer, Namespace: namespace, Inbounds: inbounds, Actions: actions, ExpiresAt: expires}
		key, e := a.federationSigningKey(ctx)
		if e != nil {
			return nil, e
		}
		signed, e := agentwire.SignFederationGrant(grant, key)
		if e != nil {
			return nil, e
		}
		token := newID() + newID()
		name := text(p, "name")
		if name == "" {
			name = "Agent管理分享"
		}
		rec, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_federationAgentShares", ID: id, OwnerID: u.ID, Version: old.Version, Data: map[string]any{"name": name, "signed_grant": signed, "token_hash": hashOpaque(token), "enabled": false, "revoked": false}})
		if e != nil {
			return nil, e
		}
		task, e := a.queue(ctx, u, server.ID, "federation.grant", map[string]any{"signed_grant": signed})
		if e != nil {
			return nil, e
		}
		rec.Data["install_task"] = task.ID
		if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
			return nil, e
		}
		_ = a.federationView(ctx, id, map[string]any{"name": name, "direction": "owner", "status": "授权下发中", "scope": "agent_management", "serverId": server.ID, "namespace": namespace})
		return map[string]any{"id": id, "share_id": id, "token": token, "owner_url": a.Config.PublicURL, "install_task_id": task.ID, "status": "pending", "agent_public_key": agentPublic, "scope": "agent_management"}, nil
	case "federation.agent.revoke":
		a.mu.Lock()
		defer a.mu.Unlock()
		rec, e := a.DB.GetRecord(ctx, "_federationAgentShares", in.TargetID)
		if e != nil {
			return nil, e
		}
		signed, e := signedGrantOf(rec)
		if e != nil {
			return nil, e
		}
		signed.Grant.Revoked = true
		signed.Grant.Revision++
		key, e := a.federationSigningKey(ctx)
		if e != nil {
			return nil, e
		}
		signed, e = agentwire.SignFederationGrant(signed.Grant, key)
		if e != nil {
			return nil, e
		}
		rec.Data["revoked"] = true
		rec.Data["enabled"] = false
		rec.Data["signed_grant"] = signed
		if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
			return nil, e
		}
		task, e := a.queue(ctx, u, signed.Grant.ServerID, "federation.grant", map[string]any{"signed_grant": signed})
		_ = a.federationView(ctx, rec.ID, map[string]any{"name": text(rec.Data, "name"), "scope": "agent_management", "direction": "owner", "status": "已撤销", "namespace": signed.Grant.Namespace})
		return map[string]any{"revoked": true, "agent_update_task_id": task.ID, "existing_inbounds_retained": true}, e
	case "federation.agent.connect":
		base := strings.TrimRight(text(p, "ownerUrl"), "/")
		parsed, e := url.Parse(base)
		if _, err := secureOrigin(base); err != nil || e != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("拥有方必须是HTTPS主控来源")
		}
		shareID := text(p, "shareId")
		token := text(p, "token")
		if !federationSafeName(shareID) || len(token) < 24 {
			return nil, errors.New("分享凭据无效")
		}
		var response struct {
			SignedGrant agentwire.SignedFederationGrant `json:"signed_grant"`
		}
		if e = a.federationRemote(ctx, base, shareID, token, "GET", "", nil, &response); e != nil {
			return nil, e
		}
		if e = a.validateConsumerGrant(response.SignedGrant, shareID, ""); e != nil {
			return nil, e
		}
		id := in.TargetID
		if id == "" {
			id = newID()
		}
		old, e := a.DB.GetRecord(ctx, "_federationAgentConsumers", id)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return nil, e
		}
		if old.ID != "" {
			if e = a.validateConsumerGrant(response.SignedGrant, shareID, text(old.Data, "owner_signing_key")); e != nil {
				return nil, e
			}
		}
		name := text(p, "name")
		if name == "" {
			name = "共享Agent"
		}
		_, e = a.DB.SaveRecord(ctx, store.Record{Collection: "_federationAgentConsumers", ID: id, OwnerID: u.ID, Version: old.Version, Data: map[string]any{"name": name, "owner_url": base, "share_id": shareID, "token": token, "signed_grant": response.SignedGrant, "owner_signing_key": response.SignedGrant.OwnerPublicKey, "enabled": true}})
		if e != nil {
			return nil, e
		}
		_ = a.federationView(ctx, id, map[string]any{"name": name, "direction": "consumer", "status": "已接入", "scope": "agent_management", "namespace": response.SignedGrant.Grant.Namespace})
		return map[string]any{"id": id, "namespace": response.SignedGrant.Grant.Namespace, "actions": response.SignedGrant.Grant.Actions, "inbounds": response.SignedGrant.Grant.Inbounds, "agent_public_key": response.SignedGrant.Grant.AgentPublicKey}, nil
	case "federation.agent.execute":
		return a.submitConsumerFederation(ctx, u, in.TargetID, p)
	case "federation.agent.result":
		return a.readConsumerFederation(ctx, u, in.TargetID)
	}
	return nil, errors.New("不支持的Agent联邦操作")
}

func federationSafeName(s string) bool {
	if s == "" || len(s) > 120 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func (a *App) waitFederationTask(ctx context.Context, id string, timeout time.Duration) (store.Task, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		task, e := a.DB.GetTask(ctx, id)
		if e != nil {
			return task, e
		}
		switch task.Status {
		case "success":
			return task, nil
		case "failed", "unsupported", "unknown":
			return task, errors.New(task.Error)
		}
		select {
		case <-ctx.Done():
			return task, ctx.Err()
		case <-deadline.C:
			return task, errors.New("节点任务尚未完成，请在任务页核对实际结果")
		case <-tick.C:
		}
	}
}

func (a *App) activeFederationAgentShare(ctx context.Context, id, token string) (store.Record, agentwire.SignedFederationGrant, error) {
	rec, e := a.DB.GetRecord(ctx, "_federationAgentShares", id)
	if e != nil || !constant(text(rec.Data, "token_hash"), hashOpaque(token)) || boolean(rec.Data, "revoked") {
		return rec, agentwire.SignedFederationGrant{}, errors.New("分享已撤销或凭据无效")
	}
	signed, e := signedGrantOf(rec)
	if e != nil || agentwire.VerifyFederationGrant(signed) != nil || signed.Grant.Revoked || (signed.Grant.ExpiresAt > 0 && signed.Grant.ExpiresAt <= time.Now().Unix()) {
		return rec, signed, errors.New("分享授权无效或已过期")
	}
	if !boolean(rec.Data, "enabled") {
		task, e := a.DB.GetTask(ctx, text(rec.Data, "install_task"))
		if e != nil || task.Status != "success" {
			return rec, signed, errors.New("节点尚未确认分享授权")
		}
		rec.Data["enabled"] = true
		updated, e := a.DB.SaveRecord(ctx, rec)
		if e == nil {
			rec = updated
		} else {
			return rec, signed, e
		}
	}
	return rec, signed, nil
}
func bearerShare(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(value, "Bearer ")
}
func (a *App) federationAgentDescribe(w http.ResponseWriter, r *http.Request) {
	_, signed, e := a.activeFederationAgentShare(r.Context(), r.PathValue("id"), bearerShare(r))
	if e != nil {
		fail(w, 403, "share_denied", e.Error())
		return
	}
	respond(w, 200, map[string]any{"signed_grant": signed})
}

func (a *App) federationAgentForward(w http.ResponseWriter, r *http.Request) {
	var envelope agentwire.FederationEnvelope
	if !decode(w, r, &envelope) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, signed, e := a.activeFederationAgentShare(r.Context(), r.PathValue("id"), bearerShare(r))
	if e != nil {
		fail(w, 403, "share_denied", e.Error())
		return
	}
	if envelope.ShareID != rec.ID || envelope.ConsumerPublicKey != signed.Grant.ConsumerPublicKey || !federationSafeName(envelope.RequestID) {
		fail(w, 403, "scope_denied", "请求身份不在授权范围内")
		return
	}
	b, _ := json.Marshal(envelope)
	hash := hashOpaque(string(b))
	jobID := "fedjob-" + hashOpaque(rec.ID + "/" + envelope.RequestID)[:32]
	job, e := a.DB.GetRecord(r.Context(), "_federationAgentJobs", jobID)
	if e == nil {
		if text(job.Data, "envelope_hash") != hash {
			fail(w, 409, "request_conflict", "同一请求标识不能用于另一段密文")
			return
		}
		respond(w, 202, map[string]any{"job_id": jobID})
		return
	}
	if !errors.Is(e, store.ErrNotFound) {
		fail(w, 500, "storage_error", "转发记录读取失败")
		return
	}
	cmd := agentwire.Command{ID: jobID, Action: "federation.execute", Params: map[string]any{"envelope": envelope}}
	input, _ := json.Marshal(cmd)
	task := store.Task{ID: jobID, ServerID: signed.Grant.ServerID, ActorID: rec.OwnerID, Kind: "federation.execute", Status: "queued", Input: input, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	previous, lookupErr := a.DB.GetTask(r.Context(), jobID)
	if lookupErr == nil {
		if previous.Kind != task.Kind || previous.ServerID != task.ServerID || !bytes.Equal(previous.Input, task.Input) {
			fail(w, 409, "request_conflict", "已有任务与转发请求不一致")
			return
		}
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		fail(w, 500, "storage_error", "转发任务读取失败")
		return
	} else if _, e = a.DB.SaveTask(r.Context(), task); e != nil {
		fail(w, 500, "storage_error", "转发任务建立失败")
		return
	}
	_, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_federationAgentJobs", ID: jobID, Data: map[string]any{"share_id": rec.ID, "consumer_public_key": envelope.ConsumerPublicKey, "envelope_hash": hash}})
	if e != nil {
		fail(w, 500, "storage_error", "转发记录建立失败")
		return
	}
	respond(w, 202, map[string]any{"job_id": jobID})
}

func (a *App) federationAgentResult(w http.ResponseWriter, r *http.Request) {
	rec, signed, e := a.activeFederationAgentShare(r.Context(), r.PathValue("id"), bearerShare(r))
	if e != nil {
		fail(w, 403, "share_denied", e.Error())
		return
	}
	job, e := a.DB.GetRecord(r.Context(), "_federationAgentJobs", r.PathValue("job"))
	if e != nil || text(job.Data, "share_id") != rec.ID || text(job.Data, "consumer_public_key") != signed.Grant.ConsumerPublicKey {
		fail(w, 404, "not_found", "转发结果不存在")
		return
	}
	task, e := a.DB.GetTask(r.Context(), job.ID)
	if e != nil || task.ServerID != signed.Grant.ServerID || task.Kind != "federation.execute" {
		fail(w, 404, "not_found", "转发结果不存在")
		return
	}
	if task.LogsDeleted {
		fail(w, http.StatusGone, "logs_deleted", "任务结果已清理；原请求不会再次执行")
		return
	}
	if task.Status == "queued" || task.Status == "running" {
		respond(w, 200, map[string]any{"status": task.Status, "pending": true})
		return
	}
	if task.Status != "success" {
		respond(w, 200, map[string]any{"status": task.Status, "error": task.Error, "pending": false})
		return
	}
	var data map[string]any
	if json.Unmarshal(task.Result, &data) != nil {
		fail(w, 500, "result_error", "节点返回无效密文结果")
		return
	}
	respond(w, 200, map[string]any{"status": "success", "packet": data["packet"], "pending": false})
}

func (a *App) federationTaskPermitted(ctx context.Context, task store.Task) bool {
	if task.Kind != "federation.execute" {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var command agentwire.Command
	if json.Unmarshal(task.Input, &command) != nil {
		return false
	}
	var envelope agentwire.FederationEnvelope
	b, err := json.Marshal(command.Params["envelope"])
	if err != nil || json.Unmarshal(b, &envelope) != nil {
		return false
	}
	rec, err := a.DB.GetRecord(ctx, "_federationAgentShares", envelope.ShareID)
	if err != nil || boolean(rec.Data, "revoked") || !boolean(rec.Data, "enabled") {
		return false
	}
	signed, err := signedGrantOf(rec)
	if err != nil || agentwire.VerifyFederationGrant(signed) != nil {
		return false
	}
	g := signed.Grant
	return !g.Revoked && g.ServerID == task.ServerID && g.ConsumerPublicKey == envelope.ConsumerPublicKey && (g.ExpiresAt == 0 || g.ExpiresAt > time.Now().Unix())
}

func (a *App) federationRemote(ctx context.Context, base, share, token, method, suffix string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+"/api/federation/agent/"+url.PathEscape(share)+suffix, reader)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("联邦端点不能重定向") }}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("无法连接拥有方主控")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("拥有方返回HTTP %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, agentwire.MaxPacket*2+1))
	if e != nil || len(b) > agentwire.MaxPacket*2 {
		return errors.New("联邦响应读取失败")
	}
	return json.Unmarshal(b, out)
}
func (a *App) validateConsumerGrant(signed agentwire.SignedFederationGrant, share, pin string) error {
	if e := agentwire.VerifyFederationGrant(signed); e != nil {
		return e
	}
	g := signed.Grant
	if g.Protocol != agentwire.FederationProtocol || g.ID != share || g.ConsumerPublicKey != a.MasterPublic || g.Revoked || (g.ExpiresAt > 0 && g.ExpiresAt <= time.Now().Unix()) || g.Revision == 0 || (pin != "" && pin != signed.OwnerPublicKey) {
		return errors.New("拥有方授权与消费者身份不匹配")
	}
	if _, e := agentwire.NewClient(g.AgentPublicKey); e != nil {
		return e
	}
	return nil
}

func (a *App) submitConsumerFederation(ctx context.Context, u store.User, id string, p map[string]any) (map[string]any, error) {
	peer, e := a.DB.GetRecord(ctx, "_federationAgentConsumers", id)
	if e != nil || !boolean(peer.Data, "enabled") {
		return nil, errors.New("共享Agent尚未接入")
	}
	var described struct {
		SignedGrant agentwire.SignedFederationGrant `json:"signed_grant"`
	}
	if e = a.federationRemote(ctx, text(peer.Data, "owner_url"), text(peer.Data, "share_id"), text(peer.Data, "token"), "GET", "", nil, &described); e != nil {
		return nil, e
	}
	if e = a.validateConsumerGrant(described.SignedGrant, text(peer.Data, "share_id"), text(peer.Data, "owner_signing_key")); e != nil {
		return nil, e
	}
	g := described.SignedGrant.Grant
	action := text(p, "action")
	allowed := false
	for _, v := range g.Actions {
		if v == action {
			allowed = true
		}
	}
	if !allowed || !scopedFederationAction(action) {
		return nil, errors.New("动作不在共享授权内")
	}
	params, _ := p["params"].(map[string]any)
	ch, e := agentwire.NewClient(g.AgentPublicKey)
	if e != nil {
		return nil, e
	}
	command := agentwire.Command{ID: newID(), Action: action, Params: params}
	request := agentwire.FederationRequest{Protocol: agentwire.FederationProtocol, ShareID: g.ID, GrantRevision: g.Revision, Namespace: g.Namespace, AgentPublicKey: g.AgentPublicKey, ConsumerPublicKey: a.MasterPublic, EphemeralPublicKey: ch.PublicKey(), IssuedAt: time.Now().Unix(), Command: command}
	request.Proof, e = agentwire.FederationProof(a.MasterPrivate, g.AgentPublicKey, request)
	if e != nil {
		return nil, e
	}
	packet, e := ch.Seal(request)
	if e != nil {
		return nil, e
	}
	state, e := ch.ClientState()
	if e != nil {
		return nil, e
	}
	envelope := agentwire.FederationEnvelope{RequestID: command.ID, ShareID: g.ID, ConsumerPublicKey: a.MasterPublic, Hello: agentwire.Hello{PublicKey: ch.PublicKey(), Packet: packet}}
	pending, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_federationAgentRequests", ID: command.ID, OwnerID: u.ID, Data: map[string]any{"peer_id": peer.ID, "agent_public_key": g.AgentPublicKey, "client_state": state, "envelope": envelope, "status": "prepared"}})
	if e != nil {
		return nil, e
	}
	var response struct {
		JobID string `json:"job_id"`
	}
	if e = a.federationRemote(ctx, text(peer.Data, "owner_url"), g.ID, text(peer.Data, "token"), "POST", "/forward", envelope, &response); e != nil {
		return map[string]any{"request_id": command.ID, "status": "unknown", "pending": true, "error": e.Error()}, nil
	}
	pending.Data["owner_job_id"] = response.JobID
	pending.Data["status"] = "queued"
	if _, e = a.DB.SaveRecord(ctx, pending); e != nil {
		return nil, e
	}
	return map[string]any{"request_id": command.ID, "owner_job_id": response.JobID, "status": "queued", "pending": true}, nil
}

func (a *App) readConsumerFederation(ctx context.Context, u store.User, id string) (map[string]any, error) {
	rec, e := a.DB.GetRecord(ctx, "_federationAgentRequests", id)
	if e != nil || rec.OwnerID != u.ID {
		return nil, errors.New("没有此联邦请求的访问权限")
	}
	if rec.Data["result"] != nil {
		return map[string]any{"pending": false, "result": rec.Data["result"]}, nil
	}
	peer, e := a.DB.GetRecord(ctx, "_federationAgentConsumers", text(rec.Data, "peer_id"))
	if e != nil || !boolean(peer.Data, "enabled") {
		return nil, errors.New("共享Agent已断开")
	}
	if text(rec.Data, "owner_job_id") == "" {
		var response struct {
			JobID string `json:"job_id"`
		}
		if e = a.federationRemote(ctx, text(peer.Data, "owner_url"), text(peer.Data, "share_id"), text(peer.Data, "token"), "POST", "/forward", rec.Data["envelope"], &response); e != nil {
			return nil, e
		}
		rec.Data["owner_job_id"] = response.JobID
		updated, e := a.DB.SaveRecord(ctx, rec)
		if e != nil {
			return nil, e
		}
		rec = updated
	}
	var response struct {
		Status  string           `json:"status"`
		Pending bool             `json:"pending"`
		Error   string           `json:"error"`
		Packet  agentwire.Packet `json:"packet"`
	}
	if e = a.federationRemote(ctx, text(peer.Data, "owner_url"), text(peer.Data, "share_id"), text(peer.Data, "token"), "GET", "/results/"+url.PathEscape(text(rec.Data, "owner_job_id")), nil, &response); e != nil {
		return nil, e
	}
	if response.Pending {
		return map[string]any{"pending": true, "status": response.Status, "request_id": id}, nil
	}
	if response.Status != "success" {
		return map[string]any{"pending": false, "status": response.Status}, errors.New(response.Error)
	}
	var state agentwire.ClientState
	b, _ := json.Marshal(rec.Data["client_state"])
	if e = json.Unmarshal(b, &state); e != nil {
		return nil, e
	}
	ch, e := agentwire.RestoreClient(text(rec.Data, "agent_public_key"), state)
	if e != nil {
		return nil, e
	}
	var result agentwire.Result
	if e = ch.Open(response.Packet, &result); e != nil {
		return nil, e
	}
	if result.ID != rec.ID {
		return nil, errors.New("联邦结果身份不匹配")
	}
	rec.Data["result"] = result
	rec.Data["status"] = result.Status
	delete(rec.Data, "client_state")
	delete(rec.Data, "envelope")
	if _, e = a.DB.SaveRecord(ctx, rec); e != nil {
		return nil, e
	}
	return map[string]any{"pending": false, "result": result}, nil
}
