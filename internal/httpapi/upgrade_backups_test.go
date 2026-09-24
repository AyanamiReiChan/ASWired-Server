package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/internal/upgradebackups"
)

func upgradeBackupFixture(t *testing.T) (*App, http.Handler, string) {
	t.Helper()
	a, handler, token := controllerFixture(t)
	a.upgradeBackupClient = &upgradebackups.Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	return a, handler, token
}

func saveUpgradeBackupStatus(t *testing.T, a *App, deletable bool) {
	t.Helper()
	value := upgradebackups.Status{Phase: "completed", Items: []upgradebackups.Item{{ID: "20260924T120000Z", CreatedAt: "2026-09-24T12:00:00Z", PreviousVersion: "v1.0.8", SizeBytes: 123, Files: []upgradebackups.File{{Name: "data.tar.gz", SizeBytes: 123}}, Deletable: deletable}}, TotalSizeBytes: 123}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.upgradeBackupClient.StateDir, upgradebackups.StatusFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeBackupsRequireAdminWebSession(t *testing.T) {
	a, handler, token := upgradeBackupFixture(t)
	ctx := context.Background()
	member := store.User{ID: "upgrade-backup-member", Username: "upgrade-backup-member", PasswordHash: "test", Role: "user", TokenVersion: 1}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/system/upgrade-backups", nil},
		{http.MethodPost, "/api/system/upgrade-backups/refresh", nil},
		{http.MethodDelete, "/api/system/upgrade-backups/20260924T120000Z", map[string]any{"confirm": "20260924T120000Z"}},
	} {
		requireStatus(t, controllerRequest(t, handler, request.method, request.path, "", request.body), 401)
		requireStatus(t, controllerRequest(t, handler, request.method, request.path, memberToken, request.body), 403)
		for _, scopes := range [][]string{{"read"}, {"write"}, {"read", "write"}} {
			created := controllerRequest(t, handler, http.MethodPost, "/api/actions", token, map[string]any{"action": "token.create", "params": map[string]any{"name": "backup-management-test", "scopes": scopes}})
			requireStatus(t, created, 200)
			apiToken := text(responseMap(t, created), "token")
			denied := controllerRequest(t, handler, request.method, request.path, apiToken, request.body)
			requireStatus(t, denied, 403)
			if !strings.Contains(denied.Body.String(), "session_required") {
				t.Fatal("API token denial was not session-specific", denied.Body)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(a.upgradeBackupClient.DataDir, upgradebackups.RequestFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unauthorized operation queued a privileged request", err)
	}
	response := controllerRequest(t, handler, http.MethodGet, "/api/system/upgrade-backups", token, nil)
	requireStatus(t, response, 200)
	status := responseMap(t, response)
	if !boolean(status, "supported") || text(status, "phase") != "idle" || len(status["items"].([]any)) != 0 || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("initial session status invalid", status)
	}
}

func TestUpgradeBackupDeleteRequiresExactConfirmationAndAuditsOnlyQueueing(t *testing.T) {
	a, handler, token := upgradeBackupFixture(t)
	id := "20260924T120000Z"
	path := "/api/system/upgrade-backups/" + id
	saveUpgradeBackupStatus(t, a, true)
	for _, body := range []any{nil, map[string]any{}, map[string]any{"confirm": true}, map[string]any{"confirm": "wrong"}, map[string]any{"confirm": id + " "}} {
		requireStatus(t, controllerRequest(t, handler, http.MethodDelete, path, token, body), 400)
	}
	for _, value := range []string{"20260230T120000Z", id + "/..", id + "\\..", id + ";id", id + "\n"} {
		requireStatus(t, controllerRequest(t, handler, http.MethodDelete, "/api/system/upgrade-backups/"+url.PathEscape(value), token, map[string]any{"confirm": value}), 400)
	}
	saveUpgradeBackupStatus(t, a, false)
	requireStatus(t, controllerRequest(t, handler, http.MethodDelete, path, token, map[string]any{"confirm": id}), 409)
	missing := "20260924T120001Z"
	requireStatus(t, controllerRequest(t, handler, http.MethodDelete, "/api/system/upgrade-backups/"+missing, token, map[string]any{"confirm": missing}), 404)
	saveUpgradeBackupStatus(t, a, true)
	accepted := controllerRequest(t, handler, http.MethodDelete, path, token, map[string]any{"confirm": id})
	requireStatus(t, accepted, 202)
	status := responseMap(t, accepted)
	if text(status, "phase") != "queued" || text(status, "operation") != "delete" || text(status, "backupId") != id || len(text(status, "requestId")) != 32 {
		t.Fatal("delete response claimed completion or lost request identity", status)
	}
	requireStatus(t, controllerRequest(t, handler, http.MethodDelete, path, token, map[string]any{"confirm": id}), 409)
	requireStatus(t, controllerRequest(t, handler, http.MethodPost, "/api/system/upgrade-backups/refresh", token, nil), 409)
	events, err := a.DB.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	queued := 0
	for _, event := range events {
		if strings.HasPrefix(event.Action, "upgrade.backups.") {
			if event.Action != "upgrade.backups.delete.queued" || event.Target != id || text(event.Details, "requestId") != text(status, "requestId") {
				t.Fatal("audit overstated completion or lost reviewed target", event)
			}
			queued++
		}
	}
	if queued != 1 {
		t.Fatal("missing or duplicate queued audit", queued)
	}
}

func TestUpgradeBackupRefreshConcurrencyUnsupportedAndFailedState(t *testing.T) {
	a, handler, token := upgradeBackupFixture(t)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			response := controllerRequest(t, handler, http.MethodPost, "/api/system/upgrade-backups/refresh", token, nil)
			if response.Code == 202 {
				accepted.Add(1)
			} else if response.Code != 409 {
				t.Errorf("unexpected concurrent response: %d %s", response.Code, response.Body)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("multiple privileged requests queued", accepted.Load())
	}
	if err := os.Remove(filepath.Join(a.upgradeBackupClient.DataDir, upgradebackups.RequestFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.upgradeBackupClient.StateDir, upgradebackups.StatusFile), []byte(`{"phase":"failed","operation":"list","requestId":"","backupId":"","message":"worker unavailable","items":[],"totalSizeBytes":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	failed := responseMap(t, controllerRequest(t, handler, http.MethodGet, "/api/system/upgrade-backups", token, nil))
	if text(failed, "phase") != "failed" || text(failed, "message") != "worker unavailable" {
		t.Fatal("worker failure hidden", failed)
	}
	if err := os.WriteFile(filepath.Join(a.upgradeBackupClient.StateDir, "status.json"), []byte(`{"phase":"updating"}`), 0600); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, handler, http.MethodPost, "/api/system/upgrade-backups/refresh", token, nil), 409)
	a.upgradeBackupClient.Ready = func(context.Context) error { return errors.New("service not installed") }
	unsupported := responseMap(t, controllerRequest(t, handler, http.MethodGet, "/api/system/upgrade-backups", token, nil))
	if boolean(unsupported, "supported") || text(unsupported, "reason") != "service not installed" || unsupported["items"] == nil {
		t.Fatal("old install status invalid", unsupported)
	}
	requireStatus(t, controllerRequest(t, handler, http.MethodPost, "/api/system/upgrade-backups/refresh", token, nil), 503)
}
