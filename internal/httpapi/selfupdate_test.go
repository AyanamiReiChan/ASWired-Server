package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/releases"
	"github.com/AyanamiReiChan/ASWired-Server/internal/selfupdate"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestControllerUpdateRequiresAdminAndReviewedVersion(t *testing.T) {
	a, h, admin := controllerFixture(t)
	calls := 0
	a.resolveRelease = func(context.Context, bool) (releases.Info, error) {
		calls++
		return releases.Info{Version: "v99.0.0", URL: "https://github.com/AyanamiReiChan/ASWired-Release/releases/tag/v99.0.0"}, nil
	}
	a.updateClient = &selfupdate.Client{DataDir: t.TempDir(), StateDir: t.TempDir(), Ready: func(context.Context) error { return nil }}
	request := map[string]any{"action": "system.update", "params": map[string]any{"apply": true, "version": "v99.0.0"}}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", "", request), 401)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/system/update", "", nil), 401)
	hash, err := auth.HashPassword("selfupdate-test-member-password")
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{ID: "selfupdate-member", Username: "selfupdate-member", Role: "user", TokenVersion: 1, PasswordHash: hash}
	if err := a.DB.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	member, err := a.Signer.Issue(u.ID, u.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", member, request), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/system/update", member, nil), 403)
	if calls != 0 {
		t.Fatal("unauthorized release fetch")
	}
	request["params"] = map[string]any{"apply": true, "version": "v98.0.0"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", admin, request), 400)
	if _, err := os.Stat(filepath.Join(a.updateClient.DataDir, "update-request.json")); !os.IsNotExist(err) {
		t.Fatal("unreviewed version queued")
	}
	request["params"] = map[string]any{"apply": true, "version": "v99.0.0"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", admin, request), 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", admin, request), 400)
	before := calls
	requireStatus(t, controllerRequest(t, h, "GET", "/api/system/update", admin, nil), 200)
	if calls != before {
		t.Fatal("status polling fetched GitHub")
	}
}
