package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) accountApplication(ctx context.Context, u store.User) (string, error) {
	rec, err := a.DB.GetRecord(ctx, "members", u.ID)
	if errors.Is(err, store.ErrNotFound) {
		return "aswired", nil
	}
	if err != nil {
		return "", err
	}
	app := text(rec.Data, "application")
	if app == "" {
		app = "aswired"
	}
	if app != "aswired" && app != "komari" {
		return "", store.ErrInvalid
	}
	return app, nil
}

func (a *App) maintainKomariSessions(ctx context.Context, now time.Time) {
	for _, collection := range []string{"_komariTickets", "_komariSessions"} {
		records, err := a.DB.ListRecords(ctx, collection, "")
		if err != nil {
			continue
		}
		for _, rec := range records {
			expires, err := time.Parse(time.RFC3339Nano, text(rec.Data, "expiresAt"))
			if err != nil || !expires.After(now) {
				_ = a.DB.ConsumeRecord(ctx, rec)
			}
		}
	}
}
func (a *App) permittedAdmin(u store.User) bool {
	if u.Role != "admin" || len(a.Config.AdminUsernames) == 0 {
		return true
	}
	for _, name := range a.Config.AdminUsernames {
		if strings.EqualFold(strings.TrimSpace(u.Username), name) {
			return true
		}
	}
	return false
}
func (a *App) workspaceAccount(ctx context.Context, u store.User) bool {
	app, err := a.accountApplication(ctx, u)
	return err == nil && app == "aswired" && a.permittedAdmin(u)
}
func (a *App) issueKomari(w http.ResponseWriter, u store.User) {
	if a.Config.KomariPublicURL == "" || a.Config.KomariBridgeSecret == "" {
		fail(w, 503, "probe_unavailable", "探针服务尚未配置")
		return
	}
	if u.Role != "user" || u.Disabled {
		fail(w, 403, "forbidden", "账户类型不允许进入探针")
		return
	}
	ticket := newID() + newID()
	_, err := a.DB.SaveRecord(context.Background(), store.Record{Collection: "_komariTickets", ID: hashOpaque(ticket), OwnerID: u.ID, Data: map[string]any{"tokenVersion": u.TokenVersion, "expiresAt": time.Now().Add(time.Minute).UTC()}})
	if err != nil {
		fail(w, 503, "storage_error", "无法建立探针登录请求")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, map[string]any{"kind": "komari", "action": a.Config.KomariPublicURL + "/auth/aswired/session", "ticket": ticket})
}
func (a *App) komariBridge(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		header := r.Header.Get("Authorization")
		if a.Config.KomariPublicURL == "" || len(a.Config.KomariBridgeSecret) < 32 || !strings.HasPrefix(header, "Bearer ") || !constant(strings.TrimPrefix(header, "Bearer "), a.Config.KomariBridgeSecret) {
			fail(w, 401, "unauthorized", "无效的服务凭据")
			return
		}
		next(w, r)
	}
}
func (a *App) komariSessionUser(ctx context.Context, rec store.Record) (store.User, error) {
	expires, err := time.Parse(time.RFC3339Nano, text(rec.Data, "expiresAt"))
	if err != nil || !expires.After(time.Now()) {
		return store.User{}, store.ErrNotFound
	}
	u, err := a.DB.UserByID(ctx, rec.OwnerID)
	if err != nil {
		return u, err
	}
	app, err := a.accountApplication(ctx, u)
	if err != nil || u.Disabled || u.Role != "user" || app != "komari" || int64(number(rec.Data, "tokenVersion")) != u.TokenVersion {
		return u, store.ErrNotFound
	}
	return u, nil
}
func (a *App) komariRedeem(w http.ResponseWriter, r *http.Request) {
	var in struct{ Ticket string }
	if !decode(w, r, &in) {
		return
	}
	if len(in.Ticket) < 32 || len(in.Ticket) > 256 {
		fail(w, 401, "invalid_ticket", "登录请求已失效")
		return
	}
	rec, err := a.DB.GetRecord(r.Context(), "_komariTickets", hashOpaque(in.Ticket))
	if err != nil {
		fail(w, 401, "invalid_ticket", "登录请求已失效")
		return
	}
	u, err := a.komariSessionUser(r.Context(), rec)
	if err != nil {
		fail(w, 401, "invalid_ticket", "登录请求已失效")
		return
	}
	if err = a.DB.ConsumeRecord(r.Context(), rec); err != nil {
		fail(w, 401, "invalid_ticket", "登录请求已失效")
		return
	}
	session := "kprobe_" + newID() + newID()
	expires := time.Now().Add(a.Config.JWTTTL).UTC()
	_, err = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_komariSessions", ID: hashOpaque(session), OwnerID: u.ID, Data: map[string]any{"tokenVersion": u.TokenVersion, "expiresAt": expires}})
	if err != nil {
		fail(w, 503, "storage_error", "无法建立探针会话")
		return
	}
	a.audit(r.Context(), u, "account.komari.login", u.ID, nil)
	respond(w, 200, map[string]any{"session": session, "expiresAt": expires, "id": u.ID, "username": u.Username})
}
func (a *App) komariIntrospect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Session   string
		Code      string
		Sensitive bool
		Logout    bool
	}
	if !decode(w, r, &in) {
		return
	}
	if !strings.HasPrefix(in.Session, "kprobe_") || len(in.Session) > 256 {
		fail(w, 401, "invalid_session", "登录已失效")
		return
	}
	rec, err := a.DB.GetRecord(r.Context(), "_komariSessions", hashOpaque(in.Session))
	if err != nil {
		fail(w, 401, "invalid_session", "登录已失效")
		return
	}
	u, err := a.komariSessionUser(r.Context(), rec)
	if err != nil {
		fail(w, 401, "invalid_session", "登录已失效")
		return
	}
	if in.Logout {
		if err := a.DB.ConsumeRecord(r.Context(), rec); err != nil && !errors.Is(err, store.ErrConflict) {
			fail(w, 503, "storage_error", "无法撤销探针会话，请重试")
			return
		}
		respond(w, 200, map[string]bool{"success": true})
		return
	}
	_, factor, err := a.loadTOTP(r.Context(), u.ID)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取账户认证状态")
		return
	}
	if in.Sensitive {
		if err = a.verifyTOTP(r.Context(), u, in.Code); err != nil {
			fail(w, 401, "invalid_totp", "请输入有效动态口令或恢复码")
			return
		}
	}
	respond(w, 200, map[string]any{"id": u.ID, "username": u.Username, "twoFactor": factor.Enabled, "expiresAt": rec.Data["expiresAt"]})
}
