package httpapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func (a *App) registerEntryGuard(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/public/auth-options", a.authOptions)
	mux.HandleFunc("POST /api/entry", a.enter)
	mux.HandleFunc("POST /api/account/turnstile/test", a.withAdmin(a.testTurnstile))
}
func (a *App) authOptions(w http.ResponseWriter, r *http.Request) {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	enabled := boolean(settings, "turnstileEnabled") && text(settings, "turnstileSiteKey") != "" && text(settings, "turnstileSecret") != ""
	siteKey := ""
	if enabled {
		siteKey = text(settings, "turnstileSiteKey")
	}
	respond(w, 200, map[string]any{"turnstileEnabled": enabled, "turnstileSiteKey": siteKey})
}
func (a *App) verifyTurnstile(r *http.Request, token string, force bool) error {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	if !force && !boolean(settings, "turnstileEnabled") {
		return nil
	}
	secret := text(settings, "turnstileSecret")
	if secret == "" || text(settings, "turnstileSiteKey") == "" {
		return errors.New("人机验证配置不完整，请由管理员恢复配置")
	}
	if token == "" || len(token) > 2048 {
		return errors.New("请先完成人机验证")
	}
	var result struct {
		Success     bool      `json:"success"`
		Hostname    string    `json:"hostname"`
		Action      string    `json:"action"`
		ChallengeTS time.Time `json:"challenge_ts"`
	}
	endpoint := defaultText(settings, "turnstileVerifyURL", "https://challenges.cloudflare.com/turnstile/v0/siteverify")
	if _, e := secureOrigin(endpoint); e != nil {
		return e
	}
	if e := a.externalJSON(r.Context(), "POST", endpoint, nil, map[string]string{"secret": secret, "response": token, "remoteip": requestIP(r)}, &result); e != nil {
		return errors.New("人机验证服务暂不可用，请重试")
	}
	hostname := text(settings, "turnstileHostname")
	if hostname == "" {
		u, _ := url.Parse(a.Config.PublicURL)
		if u != nil {
			hostname = u.Hostname()
		}
	}
	if !result.Success || !strings.EqualFold(result.Hostname, hostname) || result.Action != "login" || result.ChallengeTS.IsZero() || time.Since(result.ChallengeTS) > 5*time.Minute || time.Until(result.ChallengeTS) > time.Minute {
		return errors.New("人机验证失败、过期或来源不匹配，请重新验证")
	}
	if _, e := a.DB.SaveRecord(r.Context(), store.Record{Collection: "_turnstileTokens", ID: hashOpaque(token), Data: map[string]any{"expiresAt": time.Now().Add(5 * time.Minute).UTC()}}); e != nil {
		return errors.New("人机验证令牌已使用，请重新验证")
	}
	return nil
}
func (a *App) testTurnstile(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token string }
	if !decode(w, r, &in) {
		return
	}
	if e := a.verifyTurnstile(r, in.Token, true); e != nil {
		fail(w, 400, "invalid_turnstile", e.Error())
		return
	}
	respond(w, 200, map[string]bool{"success": true})
}
func requestIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	trusted := func(value string) bool {
		ip := net.ParseIP(value)
		if ip == nil {
			return false
		}
		for _, cidr := range strings.Split(os.Getenv("ASWIRED_TRUSTED_PROXIES"), ",") {
			_, network, e := net.ParseCIDR(strings.TrimSpace(cidr))
			if e == nil && network.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !trusted(host) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(hops[i])
		if net.ParseIP(candidate) == nil {
			return host
		}
		host = candidate
		if !trusted(candidate) {
			break
		}
	}
	return host
}
func (a *App) entryCookie(settings map[string]any, expiry string) string {
	key := hmacSHA256(a.Config.JWTSecret, "ASWired entry cookie v1\n"+text(settings, "entryKey"))
	return expiry + "." + base64.RawURLEncoding.EncodeToString(hmacSHA256(key, expiry))
}
func (a *App) grantEntry(w http.ResponseWriter, r *http.Request) {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	if !boolean(settings, "silentMode") {
		return
	}
	expires := time.Now().Add(15 * time.Minute)
	http.SetCookie(w, &http.Cookie{Name: "aswired-entry", Value: a.entryCookie(settings, strconv.FormatInt(expires.Unix(), 10)), Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.Config.PublicURL, "https://"), SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: 900})
}
func (a *App) enter(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r) {
		fail(w, 429, "rate_limited", "尝试过于频繁")
		return
	}
	var in struct{ Key string }
	if !decode(w, r, &in) {
		return
	}
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	if !boolean(settings, "silentMode") || text(settings, "entryKey") == "" || !constant(in.Key, text(settings, "entryKey")) {
		fail(w, 404, "not_found", "页面不存在")
		return
	}
	a.grantEntry(w, r)
	respond(w, 200, map[string]bool{"success": true})
}
func (a *App) entryAllowed(r *http.Request) bool {
	path := r.URL.Path
	if path == "/api/internal/komari/redeem" || path == "/api/internal/komari/introspect" {
		return true
	}
	if path == "/healthz" || path == "/api/home/pair" || path == "/api/entry" || path == "/api/setup" || path == "/api/clash/subscribe" || path == "/api/merged-subscribe" || path == "/api/temporary-subscribe" || path == "/api/generated-subscribe" || strings.HasPrefix(path, "/x/") || strings.HasPrefix(path, "/api/agent/") || strings.HasPrefix(path, "/api/federation/") || strings.HasPrefix(path, "/api/public/probe-") || path == "/api/telegram/webhook" {
		return true
	}
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	if !boolean(settings, "silentMode") {
		return true
	}
	raw := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("MM-Authorization")), "Bearer ")
	if claims, e := a.Signer.Parse(raw); e == nil {
		u, e := a.DB.UserByID(r.Context(), claims.Subject)
		if e == nil && !u.Disabled && u.TokenVersion == claims.TokenVersion {
			return true
		}
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer asw_") {
		if _, _, e := a.authenticateAPIToken(r); e == nil {
			return true
		}
	}
	cookie, e := r.Cookie("aswired-entry")
	if e != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}
	expiry, e := strconv.ParseInt(parts[0], 10, 64)
	return e == nil && expiry >= time.Now().Unix() && expiry <= time.Now().Add(16*time.Minute).Unix() && constant(cookie.Value, a.entryCookie(settings, parts[0]))
}
func validateEntrySettings(settings map[string]any) error {
	if boolean(settings, "turnstileEnabled") && (text(settings, "turnstileSiteKey") == "" || text(settings, "turnstileSecret") == "") {
		return errors.New("启用人机验证必须同时填写 Site Key 和 Secret")
	}
	if boolean(settings, "silentMode") && len(text(settings, "entryKey")) < 24 {
		return fmt.Errorf("隐藏入口密钥至少24个字符；有效订阅也可唤醒15分钟")
	}
	return nil
}
