package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enableFixtureFileLogs(t *testing.T, a *App) {
	t.Helper()
	m, e := logfiles.Open(filepath.Join(a.Config.DataDir, "logs"), 1<<20, 2)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { a.CloseFileLogs(); m.Close() })
	if e = a.EnableFileLogs(m); e != nil {
		t.Fatal(e)
	}
}
func TestFileLogsAreAuthoritativeAndTaskStateSurvivesClear(t *testing.T) {
	a, h, token := controllerFixture(t)
	enableFixtureFileLogs(t, a)
	ctx := context.Background()
	var before int
	a.DB.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&before)
	a.audit(ctx, store.User{ID: "admin"}, "record.save", "server", map[string]any{"password": "never-persist-this", "nested": map[string]any{"token": "also-private"}})
	task, e := a.DB.SaveTask(ctx, store.Task{ID: "file-log-task", Kind: "core.status", Status: "queued"})
	if e != nil {
		t.Fatal(e)
	}
	res := controllerRequest(t, h, "GET", "/api/logs/entries?stream=system", token, nil)
	requireStatus(t, res, 200)
	if !strings.Contains(res.Body.String(), "record.save") || strings.Contains(res.Body.String(), "never-persist-this") || strings.Contains(res.Body.String(), "also-private") {
		t.Fatal(res.Body)
	}
	var after int
	a.DB.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&after)
	if before != after {
		t.Fatal("new audit was stored in database")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove?stream=system", token, map[string]any{"all": true, "confirm": true}), 200)
	res = controllerRequest(t, h, "GET", "/api/logs/entries?stream=system", token, nil)
	if len(responseMap(t, res)["lines"].([]any)) != 0 {
		t.Fatal("deleted logs reappeared", res.Body)
	}
	kept, e := a.DB.GetTask(ctx, task.ID)
	if e != nil || kept.Status != "queued" {
		t.Fatal("clearing logs damaged execution state")
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/logs/entries?stream=system", "", nil), 401)
}
func TestSecurityBanEnforcementExpiryAllowlistAndFileEvents(t *testing.T) {
	a, h, token := controllerFixture(t)
	enableFixtureFileLogs(t, a)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/security/bans", token, map[string]any{"ip": "192.0.2.8", "permanent": true}), 200)
	req := httptest.NewRequest("GET", "/x/invalid", nil)
	req.RemoteAddr = "192.0.2.8:1234"
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != 403 {
		t.Fatal("ban not enforced", res.Code)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/security/bans", token, map[string]any{"ip": "127.0.0.1"}), 409)
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/security/allowlist", token, map[string]any{"addresses": []string{"192.0.2.0/24"}}), 200)
	if a.securityBlocked(req) {
		t.Fatal("allowlist ignored")
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/security/allowlist", token, map[string]any{"addresses": []string{}}), 200)
	record, _ := a.DB.GetRecord(context.Background(), "_securityBans", hashOpaque("192.0.2.8"))
	record.Data["expiresAt"] = time.Now().Add(-time.Second).Format(time.RFC3339)
	a.DB.SaveRecord(context.Background(), record)
	if a.securityBlocked(req) {
		t.Fatal("expired ban active")
	}
	req = httptest.NewRequest("GET", "/x/invalid", nil)
	req.RemoteAddr = "192.0.2.9:1234"
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	logs := controllerRequest(t, h, "GET", "/api/logs/entries?stream=security", token, nil)
	if !strings.Contains(logs.Body.String(), "subscription.probe") || !strings.Contains(logs.Body.String(), "192.0.2.9") {
		t.Fatal(logs.Body)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/logs/files/remove?stream=security", token, map[string]any{"all": true, "confirm": true}), 200)
	state := controllerRequest(t, h, "GET", "/api/security", token, nil)
	var out map[string]any
	json.Unmarshal(state.Body.Bytes(), &out)
	if out["bans"] == nil {
		t.Fatal(state.Body)
	}
}
