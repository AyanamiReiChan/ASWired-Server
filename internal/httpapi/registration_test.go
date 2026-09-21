package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func createInvite(t *testing.T, h http.Handler, admin string) map[string]any {
	t.Helper()
	w := controllerRequest(t, h, "POST", "/api/registration-invites", admin, map[string]any{"name": "friend", "expiresInDays": 7})
	requireStatus(t, w, 201)
	return responseMap(t, w)
}
func TestInvitedRegistrationAndPermissions(t *testing.T) {
	a, h, admin := controllerFixture(t)
	invite := createInvite(t, h, admin)
	code := text(invite, "code")
	id := text(invite["row"].(map[string]any), "id")
	body := map[string]any{"username": "invited-member", "password": "invited-password-2026", "inviteCode": code, "role": "admin", "disabled": false}
	w := controllerRequest(t, h, "POST", "/api/register", "", body)
	requireStatus(t, w, 200)
	session := responseMap(t, w)
	user := session["user"].(map[string]any)
	token := text(session, "token")
	if text(user, "role") != "user" {
		t.Fatal("registration escalated role")
	}
	member, err := a.DB.GetRecord(context.Background(), "members", text(user, "id"))
	if err != nil || member.OwnerID != text(user, "id") {
		t.Fatal("member missing", err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", body), 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", body), 200)
	for _, tc := range []struct{ method, path string }{{"GET", "/api/registration-invites"}, {"POST", "/api/registration-invites"}, {"DELETE", "/api/registration-invites/" + id}, {"POST", "/api/reality-targets/scan"}, {"GET", "/api/settings"}} {
		requireStatus(t, controllerRequest(t, h, tc.method, tc.path, token, map[string]any{}), 403)
	}
	for _, authToken := range []string{admin, token} {
		for _, method := range []string{"GET", "POST"} {
			requireStatus(t, controllerRequest(t, h, method, "/api/collections/"+store.RegistrationInvites, authToken, map[string]any{"row": map[string]any{"name": "bypass"}}), 404)
		}
	}
	list := controllerRequest(t, h, "GET", "/api/registration-invites", admin, nil)
	requireStatus(t, list, 200)
	if strings.Contains(list.Body.String(), code) || !strings.Contains(list.Body.String(), "invited-member") {
		t.Fatal("list leaked code or omitted use")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/registration-invites", "", map[string]any{}), 401)
}
func TestRegistrationRevocationExpiryAndRollback(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	for _, kind := range []string{"revoked", "expired", "duplicate"} {
		invite := createInvite(t, h, admin)
		id := text(invite["row"].(map[string]any), "id")
		code := text(invite, "code")
		body := map[string]any{"username": "test-admin", "password": "invited-password-2026", "inviteCode": code}
		switch kind {
		case "revoked":
			requireStatus(t, controllerRequest(t, h, "DELETE", "/api/registration-invites/"+id, admin, nil), 200)
		case "expired":
			record, _ := a.DB.GetRecord(ctx, store.RegistrationInvites, id)
			record.Data["expiresAt"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			if _, err := a.DB.SaveRecord(ctx, record); err != nil {
				t.Fatal(err)
			}
		}
		expected := 400
		if kind == "duplicate" {
			expected = 409
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", body), expected)
		if kind == "duplicate" {
			body["username"] = "after-duplicate"
			requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", body), 200)
		}
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", map[string]any{"username": "no-invite", "password": "invited-password-2026"}), 400)
	if users, _ := a.DB.ListUsers(ctx); len(users) != 2 {
		t.Fatal("invalid registrations created accounts")
	}
}

func TestRegistrationRespectsEntryAndTurnstile(t *testing.T) {
	a, h, admin := controllerFixture(t)
	invite := createInvite(t, h, admin)
	body := map[string]any{"username": "guarded-user", "password": "guarded-password-2026", "inviteCode": text(invite, "code")}
	if err := a.DB.SetSetting(context.Background(), "settings", map[string]any{"silentMode": true, "entryKey": "a-long-entry-key-for-this-test"}); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", body), 404)
	if err := a.DB.SetSetting(context.Background(), "settings", map[string]any{"turnstileEnabled": true, "turnstileSiteKey": "fixture", "turnstileSecret": "fixture"}); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/register", "", body), 400)
	if users, _ := a.DB.ListUsers(context.Background()); len(users) != 1 {
		t.Fatal("auth guard created account")
	}
	record, _ := a.DB.GetRecord(context.Background(), store.RegistrationInvites, text(invite["row"].(map[string]any), "id"))
	if text(record.Data, "status") != "active" {
		t.Fatal("guard consumed invite")
	}
}
