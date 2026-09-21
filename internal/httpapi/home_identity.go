package httpapi

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"net/http"
	"strings"
	"time"
)

func (a *App) registerHomeIdentity(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/home/{id}/pairing", a.withAdmin(a.homePairing))
	mux.HandleFunc("POST /api/home/pair", a.homePair)
	mux.HandleFunc("POST /api/home/{id}/rotate", a.withAdmin(a.homeRotate))
}
func (a *App) homeConfig(id string, cred store.Record) map[string]any {
	return map[string]any{"role": "speedtest", "mode": "remote", "server_id": id, "token": cred.Data["serverToken"], "agent_token": cred.Data["agentToken"], "master_url": strings.TrimRight(a.Config.PublicURL, "/"), "master_public_key": a.MasterPublic, "connection_mode": "websocket", "data_dir": "./home-data"}
}
func (a *App) homePairing(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	endpoint, e := a.DB.GetRecord(r.Context(), "endpoints", id)
	if e != nil || disabledStatus(endpoint.Data) {
		fail(w, 404, "not_found", "家用端不存在或已禁用")
		return
	}
	if _, e = secureOrigin(a.Config.PublicURL); e != nil {
		fail(w, 400, "https_required", "配对需要HTTPS主控地址，本机测试可使用回环地址")
		return
	}
	raw := make([]byte, 10)
	if _, e = rand.Read(raw); e != nil {
		fail(w, 500, "random_failed", "配对码生成失败")
		return
	}
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	expiry := time.Now().Add(10 * time.Minute)
	_, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_homePairings", ID: hashOpaque(code), OwnerID: current(r).ID, Data: map[string]any{"endpointId": id, "tokenVersion": current(r).TokenVersion, "expires": expiry.Unix(), "used": false}})
	if e != nil {
		fail(w, 500, "storage_error", "配对码保存失败")
		return
	}
	a.audit(r.Context(), current(r), "home.pairing.create", id, nil)
	respond(w, 200, map[string]any{"code": code, "expiresAt": expiry, "pairURL": a.Config.PublicURL, "endpointId": id})
}
func (a *App) homePair(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "配对尝试过于频繁")
		return
	}
	var in struct{ Code string }
	if !decode(w, r, &in) {
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(in.Code), "-", ""))
	if len(code) != 16 {
		fail(w, 400, "invalid_pairing", "配对码无效或已过期")
		return
	}
	pending, e := a.DB.GetRecord(r.Context(), "_homePairings", hashOpaque(code))
	if e != nil || boolean(pending.Data, "used") || number(pending.Data, "expires") < float64(time.Now().Unix()) {
		fail(w, 400, "invalid_pairing", "配对码无效、已使用或已过期")
		return
	}
	owner, e := a.DB.UserByID(r.Context(), pending.OwnerID)
	if e != nil || owner.Disabled || owner.Role != "admin" || owner.TokenVersion != int64(number(pending.Data, "tokenVersion")) {
		fail(w, 400, "invalid_pairing", "配对授权账户已失效")
		return
	}
	id := text(pending.Data, "endpointId")
	endpoint, e := a.DB.GetRecord(r.Context(), "endpoints", id)
	if e != nil || disabledStatus(endpoint.Data) {
		fail(w, 400, "invalid_pairing", "配对目标已失效")
		return
	}
	cred, e := a.DB.GetRecord(r.Context(), "_homeCredentials", id)
	batch := []store.Record{}
	if errors.Is(e, store.ErrNotFound) {
		cred = store.Record{Collection: "_homeCredentials", ID: id, Data: map[string]any{"serverToken": newID() + newID(), "agentToken": newID() + newID()}}
		batch = append(batch, cred)
	} else if e != nil {
		fail(w, 500, "storage_error", "配对凭据读取失败")
		return
	}
	pending.Data["used"] = true
	batch = append(batch, pending)
	if _, e = a.DB.CompareAndSaveRecords(r.Context(), batch); e != nil {
		fail(w, 409, "pairing_consumed", "配对码已被使用，请重新生成")
		return
	}
	a.audit(r.Context(), owner, "home.pair", id, nil)
	respond(w, 200, map[string]any{"config": a.homeConfig(id, cred)})
}
func (a *App) homeRotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	endpoint, e := a.DB.GetRecord(r.Context(), "endpoints", id)
	if e != nil || disabledStatus(endpoint.Data) {
		fail(w, 404, "not_found", "家用端不存在或已禁用")
		return
	}
	cred, e := a.DB.GetRecord(r.Context(), "_homeCredentials", id)
	if e != nil {
		fail(w, 409, "not_paired", "请先完成家用端配对")
		return
	}
	if previous := number(cred.Data, "previousExpiresAt"); previous > float64(time.Now().Unix()) {
		fail(w, 409, "rotation_in_progress", "上次轮换仍在15分钟宽限期，请等待完成后再轮换")
		return
	}
	expiry := time.Now().Add(15 * time.Minute).Unix()
	oldServer, oldAgent := text(cred.Data, "serverToken"), text(cred.Data, "agentToken")
	nextServer, nextAgent := newID()+newID(), newID()+newID()
	cred.Data = map[string]any{"serverToken": nextServer, "agentToken": nextAgent, "previousServerToken": oldServer, "previousAgentToken": oldAgent, "previousExpiresAt": expiry}
	cmd := agentwire.Command{ID: newID(), Action: "identity.rotate", Params: map[string]any{"token": nextServer, "agent_token": nextAgent, "previous_expires_at": expiry}}
	raw, _ := json.Marshal(cmd)
	task, e := a.DB.CreateTaskWithRecords(r.Context(), store.Task{ID: cmd.ID, ServerID: id, ActorID: current(r).ID, Kind: cmd.Action, Status: "queued", Input: raw}, []store.Record{cred})
	if e != nil {
		fail(w, 409, "rotation_failed", "凭据或任务保存失败，原身份保持有效，请重试")
		return
	}
	a.audit(r.Context(), current(r), "home.identity.rotate", id, map[string]any{"taskId": task.ID})
	respond(w, 202, map[string]any{"task": taskRow(task), "previousExpiresAt": expiry, "message": "新身份及下发任务已一起保存，旧身份可用15分钟；查看家用端持久更新结果。"})
}
func homeTokenAccepted(cred store.Record, token string, now time.Time) bool {
	return len(token) >= 32 && (constant(text(cred.Data, "serverToken"), token) || number(cred.Data, "previousExpiresAt") > float64(now.Unix()) && constant(text(cred.Data, "previousServerToken"), token))
}
