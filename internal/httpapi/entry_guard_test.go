package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTurnstileRequiresServerVerificationAndRejectsReplay(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	ctx := context.Background()
	var calls atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["secret"] != "test-secret" {
			t.Error("missing secret")
		}
		calls.Add(1)
		respond(w, 200, map[string]any{"success": body["response"] == "valid-token", "hostname": "localhost", "action": "login", "challenge_ts": time.Now().UTC()})
	}))
	defer fixture.Close()
	bad := controllerRequest(t, h, "PUT", "/api/settings", jwt, map[string]any{"settings": map[string]any{"turnstileEnabled": true, "turnstileSiteKey": "test-site"}})
	requireStatus(t, bad, 400)
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"turnstileEnabled": true, "turnstileSiteKey": "test-site", "turnstileSecret": "test-secret", "turnstileVerifyURL": fixture.URL})
	options := controllerRequest(t, h, "GET", "/api/public/auth-options", "", nil)
	if strings.Contains(options.Body.String(), "test-secret") {
		t.Fatal("secret leaked")
	}
	login := map[string]any{"username": "test-admin", "password": "test-admin-password-2026"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", login), 400)
	login["turnstileToken"] = "bad-token"
	requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", login), 400)
	login["turnstileToken"] = "valid-token"
	requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", login), 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", login), 400)
	if calls.Load() != 3 {
		t.Fatal("server validation did not execute")
	}
}
func TestSilentEntryCookieAndTrustedProxies(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	_ = a.DB.SetSetting(context.Background(), "settings", map[string]any{"silentMode": true, "entryKey": "fixture-entry-secret-more-than-24"})
	requireStatus(t, controllerRequest(t, h, "GET", "/api/status", "", nil), 404)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/status", jwt, nil), 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/entry", "", map[string]any{"key": "wrong"}), 404)
	entered := controllerRequest(t, h, "POST", "/api/entry", "", map[string]any{"key": "fixture-entry-secret-more-than-24"})
	requireStatus(t, entered, 200)
	cookie := entered.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("entry cookie not protected")
	}
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(cookie)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	requireStatus(t, res, 200)
	cookie.Value += "bad"
	req = httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(cookie)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	requireStatus(t, res, 404)
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.9:80"
	req.Header.Set("X-Forwarded-For", "198.51.100.12")
	if requestIP(req) != "192.0.2.9" {
		t.Fatal("untrusted forwarding spoof accepted")
	}
	t.Setenv("ASWIRED_TRUSTED_PROXIES", "127.0.0.0/8")
	req.RemoteAddr = "127.0.0.1:1000"
	req.Header.Set("X-Forwarded-For", "198.51.100.55, 192.0.2.9, 127.0.0.2")
	if requestIP(req) != "192.0.2.9" {
		t.Fatal("did not stop at first untrusted hop")
	}
}
func TestNotificationEventDeduplicationAndDisabledType(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	var delivered atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		respond(w, 200, map[string]bool{"ok": true})
	}))
	defer fixture.Close()
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"webhook": fixture.URL, "notificationEvents": map[string]any{"task.failed": true, "account.login": false}})
	initial, _ := a.DB.ListRecords(ctx, "_notificationEvents", "")
	a.emitEvent(ctx, "task.failed", "", "task-one", "test failure", nil)
	a.emitEvent(ctx, "task.failed", "", "task-one", "duplicate", nil)
	a.emitEvent(ctx, "account.login", "", "login-one", "must not deliver", nil)
	events, _ := a.DB.ListRecords(ctx, "_notificationEvents", "")
	if len(events) != len(initial)+2 {
		t.Fatal("event not deduplicated")
	}
	a.maintainNotifications(ctx)
	a.background.Wait()
	a.maintainNotifications(ctx)
	a.background.Wait()
	if delivered.Load() != 1 {
		t.Fatalf("expected one delivery, got %d", delivered.Load())
	}
}
func TestNumericRecordSaveAfterLosslessJSON(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	r := controllerRequest(t, h, "POST", "/api/collections/servers", jwt, map[string]any{"row": map[string]any{"name": "test-numeric", "address": "127.0.0.1", "limit": 1000, "cost": 1.5}})
	requireStatus(t, r, 200)
	rows, e := a.DB.ListRecords(context.Background(), "servers", "")
	if e != nil || len(rows) != 1 || number(rows[0].Data, "limit") != 1000 {
		t.Fatal("numeric CRUD rejected")
	}
}
