package httpapi

import (
	"crypto/subtle"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *App) registerQRIdentity(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/qr/start", a.qrStart)
	mux.HandleFunc("POST /api/auth/qr/poll", a.qrPoll)
	mux.HandleFunc("POST /api/auth/qr/cancel", a.qrCancel)
	mux.HandleFunc("GET /api/auth/qr/request", a.withUser(a.qrRequest))
	mux.HandleFunc("POST /api/auth/qr/approve", a.withUser(a.qrApprove))
}
func (a *App) qrStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "二维码生成过于频繁，请稍后重试")
		return
	}
	var in struct {
		DeviceName string `json:"deviceName"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.DeviceName)
	if name == "" {
		name = "ASWired 浏览器"
	}
	if len(name) > 120 {
		fail(w, 400, "invalid_name", "设备名称过长")
		return
	}
	nonce, secret := newID()+newID(), newID()+newID()
	id := membershipHash(nonce)
	verification := strings.ToUpper(newID()[:6])
	expires := time.Now().UTC().Add(2 * time.Minute)
	_, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: "_qrLogins", ID: id, Data: map[string]any{"pollSecretHash": membershipHash(secret), "deviceName": name, "verificationCode": verification, "expiresAt": expires.Unix(), "status": "pending"}})
	if e != nil {
		fail(w, 500, "storage_error", "无法创建登录二维码")
		return
	}
	respond(w, 200, map[string]any{"requestId": id, "pollSecret": secret, "qrURL": strings.TrimRight(a.Config.PublicURL, "/") + "/auth/qr?code=" + url.QueryEscape(nonce), "verificationCode": verification, "expiresAt": expires.Format(time.RFC3339), "expiresIn": 120})
}
func qrPending(rec store.Record) error {
	if number(rec.Data, "expiresAt") <= float64(time.Now().Unix()) {
		return errors.New("二维码已过期，请在原浏览器重新生成")
	}
	if text(rec.Data, "status") != "pending" {
		return errors.New("二维码已确认或已失效")
	}
	return nil
}
func (a *App) qrRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	nonce := r.URL.Query().Get("code")
	if len(nonce) < 24 || len(nonce) > 128 {
		fail(w, 400, "invalid_code", "二维码无效")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), "_qrLogins", membershipHash(nonce))
	if e != nil {
		fail(w, 404, "invalid_code", "二维码无效")
		return
	}
	if e = qrPending(rec); e != nil {
		fail(w, 410, "qr_expired", e.Error())
		return
	}
	respond(w, 200, map[string]any{"deviceName": rec.Data["deviceName"], "createdAt": rec.CreatedAt, "expiresAt": rec.Data["expiresAt"], "origin": a.Config.PublicURL, "status": "pending"})
}
func (a *App) qrApprove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Code             string `json:"code"`
		Confirmed        bool   `json:"confirmed"`
		VerificationCode string `json:"verificationCode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !in.Confirmed || len(in.Code) < 24 || len(in.Code) > 128 {
		fail(w, 400, "confirmation_required", "请确认是你正在登录的浏览器")
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), "_qrLogins", membershipHash(in.Code))
	if e != nil {
		fail(w, 404, "invalid_code", "二维码无效")
		return
	}
	if e = qrPending(rec); e != nil {
		fail(w, 410, "qr_expired", e.Error())
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToUpper(strings.TrimSpace(in.VerificationCode))), []byte(text(rec.Data, "verificationCode"))) != 1 {
		fail(w, 400, "verification_failed", "确认码不匹配，请核对原浏览器显示的六位代码")
		return
	}
	u := current(r)
	rec.OwnerID = u.ID
	rec.Data["tokenVersion"] = u.TokenVersion
	rec.Data["status"] = "approved"
	rec.Data["approvedAt"] = time.Now().UTC().Format(time.RFC3339)
	if _, e = a.DB.SaveRecord(r.Context(), rec); e != nil {
		fail(w, 409, "qr_changed", "二维码状态已改变，请重新扫码")
		return
	}
	a.audit(r.Context(), u, "auth.qr.approve", rec.ID, nil)
	respond(w, 200, map[string]any{"success": true, "message": "已确认，请回到原浏览器；此页面不会接收新的登录令牌"})
}

type qrPollInput struct {
	RequestID  string `json:"requestId"`
	PollSecret string `json:"pollSecret"`
}

func (a *App) qrReadBrowser(w http.ResponseWriter, r *http.Request) (store.Record, bool) {
	var in qrPollInput
	if !decode(w, r, &in) {
		return store.Record{}, false
	}
	if len(in.RequestID) != 64 || len(in.PollSecret) < 24 || len(in.PollSecret) > 128 {
		fail(w, 401, "qr_secret_invalid", "登录请求验证失败")
		return store.Record{}, false
	}
	rec, e := a.DB.GetRecord(r.Context(), "_qrLogins", in.RequestID)
	if e != nil || subtle.ConstantTimeCompare([]byte(membershipHash(in.PollSecret)), []byte(text(rec.Data, "pollSecretHash"))) != 1 {
		fail(w, 401, "qr_secret_invalid", "登录请求验证失败")
		return store.Record{}, false
	}
	if number(rec.Data, "expiresAt") <= float64(time.Now().Unix()) {
		fail(w, 410, "qr_expired", "二维码已过期，请重新生成")
		return store.Record{}, false
	}
	return rec, true
}
func (a *App) qrPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rec, ok := a.qrReadBrowser(w, r)
	if !ok {
		return
	}
	switch text(rec.Data, "status") {
	case "pending":
		respond(w, 200, map[string]any{"status": "pending"})
		return
	case "approved":
	default:
		fail(w, 409, "qr_consumed", "二维码已使用或取消，请重新生成")
		return
	}
	u, e := a.DB.UserByID(r.Context(), rec.OwnerID)
	if e != nil || u.Disabled || u.TokenVersion != int64(number(rec.Data, "tokenVersion")) {
		fail(w, 401, "session_expired", "确认端账户登录已失效，请重新扫码")
		return
	}
	rec.Data["status"] = "consumed"
	delete(rec.Data, "pollSecretHash")
	if _, e = a.DB.SaveRecord(r.Context(), rec); e != nil {
		fail(w, 409, "qr_consumed", "二维码已被使用，请重新生成")
		return
	}
	a.audit(r.Context(), u, "auth.qr.login", rec.ID, nil)
	a.issue(w, u)
}
func (a *App) qrCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rec, ok := a.qrReadBrowser(w, r)
	if !ok {
		return
	}
	if text(rec.Data, "status") != "pending" && text(rec.Data, "status") != "approved" {
		fail(w, 409, "qr_consumed", "二维码已使用或取消")
		return
	}
	rec.Data["status"] = "cancelled"
	delete(rec.Data, "pollSecretHash")
	if _, e := a.DB.SaveRecord(r.Context(), rec); e != nil {
		fail(w, 409, "qr_changed", "二维码状态已改变")
		return
	}
	respond(w, 200, map[string]any{"success": true})
}
