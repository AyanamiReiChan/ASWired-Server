package httpapi

import (
	"crypto/rand"
	"net/http"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) registerInvitations(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/register", a.registerUser)
	mux.HandleFunc("GET /api/registration-invites", a.withAdmin(a.invitesList))
	mux.HandleFunc("POST /api/registration-invites", a.withAdmin(a.invitesCreate))
	mux.HandleFunc("DELETE /api/registration-invites/{id}", a.withAdmin(a.invitesRevoke))
}
func (a *App) invitesList(w http.ResponseWriter, r *http.Request) {
	records, err := a.DB.ListRecords(r.Context(), store.RegistrationInvites, "")
	if err != nil {
		fail(w, 500, "storage_error", "读取邀请码失败")
		return
	}
	rows := make([]map[string]any, 0, len(records))
	for _, record := range records {
		row := rowOf(record, true)
		if text(row, "status") == "active" && !time.Now().Before(dateTime(text(row, "expiresAt"))) {
			row["status"] = "expired"
		}
		rows = append(rows, row)
	}
	respond(w, 200, map[string]any{"rows": rows})
}
func (a *App) invitesCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string
		ExpiresInDays int
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.ExpiresInDays == 0 {
		in.ExpiresInDays = 7
	}
	if len(in.Name) > 120 || in.ExpiresInDays < 1 || in.ExpiresInDays > 90 {
		fail(w, 400, "invalid_invite", "备注最多120字节，有效期为1至90天")
		return
	}
	code := "asw_inv_" + rand.Text()
	record, err := a.DB.SaveRecord(r.Context(), store.Record{Collection: store.RegistrationInvites, ID: hashOpaque(code), OwnerID: current(r).ID, Data: map[string]any{"name": in.Name, "status": "active", "expiresAt": time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour).UTC().Format(time.RFC3339Nano)}})
	if err != nil {
		fail(w, 500, "storage_error", "生成邀请码失败")
		return
	}
	a.audit(r.Context(), current(r), "registration.invite.create", record.ID, map[string]any{"expiresAt": record.Data["expiresAt"]})
	respond(w, 201, map[string]any{"code": code, "row": rowOf(record, true)})
}
func (a *App) invitesRevoke(w http.ResponseWriter, r *http.Request) {
	record, err := a.DB.GetRecord(r.Context(), store.RegistrationInvites, r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "邀请码不存在")
		return
	}
	if text(record.Data, "status") != "active" {
		fail(w, 409, "invite_inactive", "邀请码已使用或撤销")
		return
	}
	record.Data["status"] = "revoked"
	if _, err = a.DB.SaveRecord(r.Context(), record); err != nil {
		fail(w, 409, "conflict", "邀请码状态已变化，请刷新后重试")
		return
	}
	a.audit(r.Context(), current(r), "registration.invite.revoke", record.ID, nil)
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) registerUser(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
		return
	}
	var in struct{ Username, Password, InviteCode, TurnstileToken string }
	if !decode(w, r, &in) {
		return
	}
	if err := a.verifyTurnstile(r, in.TurnstileToken, false); err != nil {
		fail(w, 400, "invalid_turnstile", err.Error())
		return
	}
	if err := validCredentials(in.Username, in.Password); err != nil {
		fail(w, 400, "invalid_credentials", err.Error())
		return
	}
	code := strings.TrimSpace(in.InviteCode)
	if !strings.HasPrefix(code, "asw_inv_") || len(code) > 128 {
		fail(w, 400, "invalid_invite", "邀请码无效、已使用或已过期")
		return
	}
	record, err := a.DB.GetRecord(r.Context(), store.RegistrationInvites, hashOpaque(code))
	if err != nil || text(record.Data, "status") != "active" || !time.Now().Before(dateTime(text(record.Data, "expiresAt"))) {
		fail(w, 400, "invalid_invite", "邀请码无效、已使用或已过期")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		fail(w, 500, "password_error", "无法保存密码")
		return
	}
	u := store.User{ID: newID(), Username: strings.TrimSpace(in.Username), PasswordHash: hash, Role: "user", TokenVersion: 1}
	if err = a.DB.RegisterInvitedUser(r.Context(), record.ID, u); err != nil {
		fail(w, 409, "registration_failed", "注册失败：用户名已存在，或邀请码已失效。请检查后重试")
		return
	}
	u, err = a.DB.UserByID(r.Context(), u.ID)
	if err != nil {
		fail(w, 500, "storage_error", "无法读取账户，请尝试登录")
		return
	}
	a.audit(r.Context(), u, "account.register", u.ID, map[string]any{"inviteId": record.ID})
	a.issue(w, u)
}
