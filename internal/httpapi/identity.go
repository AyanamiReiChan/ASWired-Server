package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var ErrTOTPRequired = errors.New("请输入身份验证器验证码或恢复码")
var errTOTPInvalid = errors.New("验证码无效、已使用或已过期")

type identityState struct {
	mu         sync.Mutex
	ceremonies map[string]identityCeremony
}
type identityCeremony struct {
	Kind, UserID, Name string
	TokenVersion       int64
	Session            webauthn.SessionData
	Expires            time.Time
}
type totpSettings struct {
	Enabled        bool     `json:"enabled"`
	Secret         string   `json:"secret"`
	Pending        string   `json:"pending,omitempty"`
	PendingUntil   int64    `json:"pendingUntil,omitempty"`
	LastCounter    int64    `json:"lastCounter"`
	RecoveryHashes []string `json:"recoveryHashes,omitempty"`
}
type passkeyUser struct {
	user        store.User
	credentials []webauthn.Credential
}

func (u passkeyUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u passkeyUser) WebAuthnName() string                       { return u.user.Username }
func (u passkeyUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (a *App) identityStore() *identityState {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identity == nil {
		a.identity = &identityState{ceremonies: map[string]identityCeremony{}}
	}
	return a.identity
}
func (a *App) identityGuard(next http.HandlerFunc) http.HandlerFunc {
	return a.withUser(func(w http.ResponseWriter, r *http.Request) {
		if !a.allowAttempt(r) {
			fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
			return
		}
		next(w, r)
	})
}
func (a *App) registerIdentity(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/account/security", a.withUser(a.identityStatus))
	mux.HandleFunc("POST /api/account/totp/begin", a.identityGuard(a.totpBegin))
	mux.HandleFunc("POST /api/account/totp/confirm", a.identityGuard(a.totpConfirm))
	mux.HandleFunc("POST /api/account/totp/disable", a.identityGuard(a.totpDisable))
	mux.HandleFunc("POST /api/account/totp/recovery", a.identityGuard(a.totpRecovery))
	mux.HandleFunc("POST /api/account/passkeys/begin", a.identityGuard(a.passkeyRegisterBegin))
	mux.HandleFunc("POST /api/account/passkeys/finish", a.identityGuard(a.passkeyRegisterFinish))
	mux.HandleFunc("POST /api/account/passkeys/{id}/delete", a.identityGuard(a.passkeyDelete))
	mux.HandleFunc("POST /api/passkey/login/begin", a.passkeyLoginBegin)
	mux.HandleFunc("POST /api/passkey/login/finish", a.passkeyLoginFinish)
	mux.HandleFunc("GET /.well-known/webauthn", a.relatedOrigins)
}
func (a *App) loadTOTP(ctx context.Context, userID string) (store.Record, totpSettings, error) {
	rec, e := a.DB.GetRecord(ctx, "_identity", userID)
	if errors.Is(e, store.ErrNotFound) {
		return store.Record{Collection: "_identity", ID: userID, OwnerID: userID}, totpSettings{LastCounter: -1}, nil
	}
	if e != nil {
		return rec, totpSettings{}, e
	}
	b, e := json.Marshal(rec.Data)
	if e != nil {
		return rec, totpSettings{}, e
	}
	var settings totpSettings
	e = json.Unmarshal(b, &settings)
	return rec, settings, e
}
func (a *App) saveTOTP(ctx context.Context, rec store.Record, settings totpSettings) error {
	b, e := json.Marshal(settings)
	if e != nil {
		return e
	}
	if e = json.Unmarshal(b, &rec.Data); e != nil {
		return e
	}
	_, e = a.DB.SaveRecord(ctx, rec)
	return e
}
func totpCode(secret string, counter int64) (string, error) {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if e != nil || len(key) < 20 {
		return "", errors.New("invalid TOTP secret")
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(counter))
	h := hmac.New(sha1.New, key)
	_, _ = h.Write(b[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	n := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000), nil
}
func validTOTP(secret, code string, now time.Time, lastCounter int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	counter := now.Unix() / 30
	for _, offset := range []int64{0, -1, 1} {
		c := counter + offset
		if c <= lastCounter {
			continue
		}
		expected, e := totpCode(secret, c)
		if e == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}
func recoveryHash(code string) string {
	clean := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(code)))
	hash := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(hash[:])
}
func newRecoveryCodes() ([]string, []string, error) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		b := make([]byte, 12)
		if _, e := rand.Read(b); e != nil {
			return nil, nil, e
		}
		raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
		codes[i] = raw[:5] + "-" + raw[5:10] + "-" + raw[10:15] + "-" + raw[15:]
		hashes[i] = recoveryHash(codes[i])
	}
	return codes, hashes, nil
}

func (a *App) verifyTOTP(ctx context.Context, u store.User, code string) error {
	for attempt := 0; attempt < 3; attempt++ {
		rec, settings, e := a.loadTOTP(ctx, u.ID)
		if e != nil {
			return e
		}
		if !settings.Enabled {
			return nil
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return ErrTOTPRequired
		}
		accepted := false
		if counter, ok := validTOTP(settings.Secret, code, time.Now(), settings.LastCounter); ok {
			settings.LastCounter = counter
			accepted = true
		} else {
			hash := recoveryHash(code)
			for i, stored := range settings.RecoveryHashes {
				if subtle.ConstantTimeCompare([]byte(hash), []byte(stored)) == 1 {
					settings.RecoveryHashes = append(settings.RecoveryHashes[:i], settings.RecoveryHashes[i+1:]...)
					accepted = true
					break
				}
			}
		}
		if !accepted {
			return errTOTPInvalid
		}
		if e = a.saveTOTP(ctx, rec, settings); errors.Is(e, store.ErrConflict) {
			continue
		} else {
			return e
		}
	}
	return errors.New("身份设置已更新，请重试")
}
func (a *App) reauth(r *http.Request, u store.User, password, code string) error {
	if !auth.VerifyPassword(u.PasswordHash, password) {
		return errors.New("当前密码不正确")
	}
	return a.verifyTOTP(r.Context(), u, code)
}
func (a *App) identityStatus(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	_, settings, e := a.loadTOTP(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "无法读取身份设置")
		return
	}
	keys, e := a.DB.ListRecords(r.Context(), "_passkeys", u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "无法读取通行密钥")
		return
	}
	items := []map[string]any{}
	for _, key := range keys {
		items = append(items, map[string]any{"id": key.ID, "name": text(key.Data, "name"), "created": key.CreatedAt, "lastUsed": key.Data["lastUsed"]})
	}
	wa, e := a.webAuthn()
	rp := ""
	if e == nil {
		rp = wa.Config.RPID
	}
	respond(w, 200, map[string]any{"totpEnabled": settings.Enabled, "recoveryRemaining": len(settings.RecoveryHashes), "passkeys": items, "passkeyAvailable": e == nil, "rpId": rp})
}
func (a *App) totpBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if e := a.reauth(r, u, in.Password, in.Code); e != nil {
		fail(w, 400, "reauth_failed", e.Error())
		return
	}
	rec, settings, e := a.loadTOTP(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	if settings.Enabled {
		fail(w, 409, "totp_enabled", "已启用两步验证，请先关闭再重新配置")
		return
	}
	b := make([]byte, 20)
	if _, e = rand.Read(b); e != nil {
		fail(w, 500, "random_error", "无法生成密钥")
		return
	}
	settings.Pending = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	settings.PendingUntil = time.Now().Add(10 * time.Minute).Unix()
	if e = a.saveTOTP(r.Context(), rec, settings); e != nil {
		fail(w, 409, "conflict", "设置已更新，请重试")
		return
	}
	values := url.Values{"secret": {settings.Pending}, "issuer": {"ASWired"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	respond(w, 200, map[string]any{"secret": settings.Pending, "uri": "otpauth://totp/" + url.PathEscape("ASWired:"+u.Username) + "?" + values.Encode(), "expiresIn": 600})
}
func (a *App) totpConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	rec, settings, e := a.loadTOTP(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	counter, ok := validTOTP(settings.Pending, strings.TrimSpace(in.Code), time.Now(), -1)
	if settings.Enabled || settings.PendingUntil < time.Now().Unix() || !ok {
		fail(w, 400, "invalid_code", "验证码无效或配置已过期")
		return
	}
	codes, hashes, e := newRecoveryCodes()
	if e != nil {
		fail(w, 500, "random_error", "生成恢复码失败")
		return
	}
	settings.Enabled = true
	settings.Secret = settings.Pending
	settings.Pending = ""
	settings.PendingUntil = 0
	settings.LastCounter = counter
	settings.RecoveryHashes = hashes
	if e = a.saveTOTP(r.Context(), rec, settings); e != nil {
		fail(w, 409, "conflict", "身份设置已更新，请重试")
		return
	}
	a.audit(r.Context(), u, "identity.totp.enable", u.ID, nil)
	respond(w, 200, map[string]any{"enabled": true, "recoveryCodes": codes})
}
func (a *App) totpDisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if e := a.reauth(r, u, in.Password, in.Code); e != nil {
		fail(w, 400, "reauth_failed", e.Error())
		return
	}
	rec, _, e := a.loadTOTP(r.Context(), u.ID)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	if e = a.saveTOTP(r.Context(), rec, totpSettings{LastCounter: -1}); e != nil {
		fail(w, 409, "conflict", "身份设置已更新，请重试")
		return
	}
	a.audit(r.Context(), u, "identity.totp.disable", u.ID, nil)
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) totpRecovery(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if e := a.reauth(r, u, in.Password, in.Code); e != nil {
		fail(w, 400, "reauth_failed", e.Error())
		return
	}
	rec, settings, e := a.loadTOTP(r.Context(), u.ID)
	if e != nil || !settings.Enabled {
		fail(w, 400, "totp_disabled", "请先启用两步验证")
		return
	}
	codes, hashes, e := newRecoveryCodes()
	if e != nil {
		fail(w, 500, "random_error", "生成失败")
		return
	}
	settings.RecoveryHashes = hashes
	if e = a.saveTOTP(r.Context(), rec, settings); e != nil {
		fail(w, 409, "conflict", "身份设置已更新，请重试")
		return
	}
	a.audit(r.Context(), u, "identity.recovery.rotate", u.ID, nil)
	respond(w, 200, map[string]any{"recoveryCodes": codes})
}

func (a *App) webAuthn() (*webauthn.WebAuthn, error) {
	public, e := url.Parse(a.Config.PublicURL)
	if e != nil {
		return nil, e
	}
	rpID := strings.TrimSpace(os.Getenv("ASWIRED_WEBAUTHN_RPID"))
	if rpID == "" {
		rpID = public.Hostname()
		if ip := net.ParseIP(rpID); ip != nil && ip.IsLoopback() {
			rpID = "localhost"
		}
	}
	origins := []string{}
	seen := map[string]bool{}
	for _, origin := range append(append([]string{}, a.Config.AllowedOrigins...), a.Config.PublicURL) {
		parsed, e := url.Parse(origin)
		if e != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			continue
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && parsed.Hostname() == "localhost") {
			continue
		}
		normalized := parsed.Scheme + "://" + parsed.Host
		if !seen[normalized] {
			origins = append(origins, normalized)
			seen[normalized] = true
		}
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "ASWired", RPOrigins: origins, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}, Timeouts: webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: 3 * time.Minute}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: 3 * time.Minute}}})
}
func (a *App) relatedOrigins(w http.ResponseWriter, r *http.Request) {
	wa, e := a.webAuthn()
	if e != nil {
		fail(w, 503, "passkey_unavailable", "请配置有效的公开域名与允许来源")
		return
	}
	respond(w, 200, map[string]any{"origins": wa.Config.RPOrigins})
}
func (a *App) passkeyAccount(ctx context.Context, u store.User) (passkeyUser, error) {
	rows, e := a.DB.ListRecords(ctx, "_passkeys", u.ID)
	if e != nil {
		return passkeyUser{}, e
	}
	result := passkeyUser{user: u}
	for _, row := range rows {
		raw, e := json.Marshal(row.Data["credential"])
		if e != nil {
			return result, e
		}
		var credential webauthn.Credential
		if e = json.Unmarshal(raw, &credential); e != nil {
			return result, e
		}
		result.credentials = append(result.credentials, credential)
	}
	return result, nil
}
func (a *App) putCeremony(c identityCeremony) (string, error) {
	s := a.identityStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, entry := range s.ceremonies {
		if entry.Expires.Before(now) {
			delete(s.ceremonies, key)
		}
	}
	if len(s.ceremonies) >= 1000 {
		return "", errors.New("身份验证请求过多，请稍后重试")
	}
	id := newID()
	c.Expires = now.Add(3 * time.Minute)
	s.ceremonies[id] = c
	return id, nil
}
func (a *App) takeCeremony(id, kind string) (identityCeremony, error) {
	s := a.identityStore()
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[id]
	delete(s.ceremonies, id)
	if !ok || c.Kind != kind || time.Now().After(c.Expires) {
		return c, errors.New("验证请求无效或已过期，请重新开始")
	}
	return c, nil
}
func (a *App) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code, Name string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if e := a.reauth(r, u, in.Password, in.Code); e != nil {
		fail(w, 400, "reauth_failed", e.Error())
		return
	}
	user, e := a.passkeyAccount(r.Context(), u)
	if e != nil {
		fail(w, 500, "storage_error", "读取通行密钥失败")
		return
	}
	if len(user.credentials) >= 20 {
		fail(w, 400, "key_limit", "最多保存20个通行密钥")
		return
	}
	wa, e := a.webAuthn()
	if e != nil {
		fail(w, 503, "passkey_unavailable", "请配置有效的公开域名与允许来源")
		return
	}
	exclude := []protocol.CredentialDescriptor{}
	for _, c := range user.credentials {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID})
	}
	options, session, e := wa.BeginRegistration(user, webauthn.WithExclusions(exclude), webauthn.WithRegistrationOrigin(r.Header.Get("Origin")))
	if e != nil {
		fail(w, 400, "passkey_begin_failed", "无法开始通行密钥注册，请使用已配置的 HTTPS 域名或 localhost")
		return
	}
	name := strings.TrimSpace(in.Name)
	if len(name) > 120 {
		name = name[:120]
	}
	if name == "" {
		name = "我的通行密钥"
	}
	id, e := a.putCeremony(identityCeremony{Kind: "register", UserID: u.ID, TokenVersion: u.TokenVersion, Name: name, Session: *session})
	if e != nil {
		fail(w, 429, "rate_limited", e.Error())
		return
	}
	respond(w, 200, map[string]any{"challengeId": id, "options": options})
}
func credentialRequest(r *http.Request, response json.RawMessage) *http.Request {
	copy := r.Clone(r.Context())
	copy.Body = io.NopCloser(bytes.NewReader(response))
	copy.ContentLength = int64(len(response))
	copy.Header = r.Header.Clone()
	copy.Header.Set("Content-Type", "application/json")
	return copy
}
func (a *App) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ChallengeID string          `json:"challengeId"`
		Response    json.RawMessage `json:"response"`
	}
	if !decode(w, r, &in) {
		return
	}
	c, e := a.takeCeremony(in.ChallengeID, "register")
	u := current(r)
	if e != nil || c.UserID != u.ID || c.TokenVersion != u.TokenVersion {
		fail(w, 400, "challenge_invalid", "注册请求已失效，请重新开始")
		return
	}
	user, e := a.passkeyAccount(r.Context(), u)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	wa, e := a.webAuthn()
	if e != nil {
		fail(w, 503, "passkey_unavailable", "通行密钥配置不可用")
		return
	}
	credential, e := wa.FinishRegistration(user, c.Session, credentialRequest(r, in.Response))
	if e != nil {
		fail(w, 400, "passkey_invalid", "通行密钥验证失败，请重新开始")
		return
	}
	raw, e := json.Marshal(credential)
	if e != nil {
		fail(w, 500, "credential_error", "凭据无法保存")
		return
	}
	var data any
	if e = json.Unmarshal(raw, &data); e != nil {
		fail(w, 500, "credential_error", "凭据无法保存")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	if _, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_passkeys", ID: id, OwnerID: u.ID, Data: map[string]any{"name": c.Name, "credential": data}}); e != nil {
		fail(w, 409, "credential_exists", "该通行密钥已经注册或保存失败")
		return
	}
	a.audit(r.Context(), u, "identity.passkey.create", id, nil)
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
		return
	}
	var in struct{ Username string }
	if !decode(w, r, &in) {
		return
	}
	u, e := a.DB.UserByUsername(r.Context(), strings.TrimSpace(in.Username))
	if e != nil || u.Disabled {
		fail(w, 400, "passkey_unavailable", "无法使用该账户的通行密钥")
		return
	}
	user, e := a.passkeyAccount(r.Context(), u)
	if e != nil || len(user.credentials) == 0 {
		fail(w, 400, "passkey_unavailable", "无法使用该账户的通行密钥")
		return
	}
	wa, e := a.webAuthn()
	if e != nil {
		fail(w, 503, "passkey_unavailable", "请配置有效的公开域名与允许来源")
		return
	}
	options, session, e := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithLoginOrigin(r.Header.Get("Origin")))
	if e != nil {
		fail(w, 400, "passkey_begin_failed", "无法开始通行密钥登录")
		return
	}
	id, e := a.putCeremony(identityCeremony{Kind: "login", UserID: u.ID, TokenVersion: u.TokenVersion, Session: *session})
	if e != nil {
		fail(w, 429, "rate_limited", e.Error())
		return
	}
	respond(w, 200, map[string]any{"challengeId": id, "options": options})
}
func (a *App) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁，请稍后再试")
		return
	}
	var in struct {
		ChallengeID string          `json:"challengeId"`
		Response    json.RawMessage `json:"response"`
	}
	if !decode(w, r, &in) {
		return
	}
	c, e := a.takeCeremony(in.ChallengeID, "login")
	if e != nil {
		fail(w, 400, "challenge_invalid", e.Error())
		return
	}
	u, e := a.DB.UserByID(r.Context(), c.UserID)
	if e != nil || u.Disabled || u.TokenVersion != c.TokenVersion {
		fail(w, 401, "session_expired", "账户状态已改变，请重新登录")
		return
	}
	user, e := a.passkeyAccount(r.Context(), u)
	if e != nil {
		fail(w, 500, "storage_error", "读取失败")
		return
	}
	wa, e := a.webAuthn()
	if e != nil {
		fail(w, 503, "passkey_unavailable", "通行密钥配置不可用")
		return
	}
	credential, e := wa.FinishLogin(user, c.Session, credentialRequest(r, in.Response))
	if e != nil || credential.Authenticator.CloneWarning {
		fail(w, 400, "passkey_invalid", "通行密钥验证失败")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(credential.ID)
	record, e := a.DB.GetRecord(r.Context(), "_passkeys", id)
	if e != nil || record.OwnerID != u.ID {
		fail(w, 400, "passkey_invalid", "通行密钥已被撤销")
		return
	}
	raw, _ := json.Marshal(credential)
	var data any
	if e = json.Unmarshal(raw, &data); e != nil {
		fail(w, 500, "credential_error", "凭据更新失败")
		return
	}
	var previous webauthn.Credential
	oldRaw, marshalErr := json.Marshal(record.Data["credential"])
	if marshalErr != nil || json.Unmarshal(oldRaw, &previous) != nil {
		fail(w, 500, "credential_error", "读取凭据失败")
		return
	}
	if previous.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= previous.Authenticator.SignCount {
		fail(w, 400, "passkey_invalid", "通行密钥计数无效，请重新验证")
		return
	}
	record.Data["credential"] = data
	record.Data["lastUsed"] = time.Now().UTC()
	if _, e = a.DB.SaveRecord(r.Context(), record); e != nil {
		fail(w, 409, "credential_changed", "通行密钥已更新，请重新登录")
		return
	}
	a.audit(r.Context(), u, "identity.passkey.login", id, nil)
	a.issue(w, u)
}
func (a *App) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	u := current(r)
	if e := a.reauth(r, u, in.Password, in.Code); e != nil {
		fail(w, 400, "reauth_failed", e.Error())
		return
	}
	rec, e := a.DB.GetRecord(r.Context(), "_passkeys", r.PathValue("id"))
	if e != nil || rec.OwnerID != u.ID {
		fail(w, 404, "not_found", "通行密钥不存在")
		return
	}
	if e = a.DB.DeleteRecord(r.Context(), "_passkeys", rec.ID); e != nil {
		fail(w, 500, "storage_error", "删除失败")
		return
	}
	a.audit(r.Context(), u, "identity.passkey.delete", rec.ID, nil)
	respond(w, 200, map[string]bool{"success": true})
}
