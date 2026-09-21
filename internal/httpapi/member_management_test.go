package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestMemberManagementListsBootstrapAndProtectsAccess(t *testing.T) {
	a, h, token := controllerFixture(t)
	res := controllerRequest(t, h, "GET", "/api/members/management", token, nil)
	requireStatus(t, res, 200)
	rows := responseMap(t, res)["rows"].([]any)
	if len(rows) != 1 || text(rows[0].(map[string]any), "username") != "test-admin" {
		t.Fatal("bootstrap admin missing")
	}
	u, err := a.DB.UserByUsername(context.Background(), "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/members/"+u.ID, token, map[string]any{"row": map[string]any{"name": "管理员昵称", "note": "test note", "recordVersion": 0}}), 200)
	updated, err := a.DB.GetRecord(context.Background(), "members", u.ID)
	if err != nil || text(updated.Data, "note") != "test note" {
		t.Fatal("bootstrap profile not created", err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/members/"+u.ID, token, map[string]any{"row": map[string]any{"note": "stale", "recordVersion": 0}}), 409)
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/members/"+u.ID, token, map[string]any{"row": map[string]any{"status": "暂停", "recordVersion": updated.Version}}), 400)
	member := store.User{ID: "ordinary", Username: "ordinary", Role: "user", PasswordHash: "hash"}
	if err = a.DB.CreateUser(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	jwt, _ := a.Signer.Issue(member.ID, 0)
	for _, spec := range []struct{ method, path string }{{"GET", "/api/members/management"}, {"PUT", "/api/members/" + u.ID}, {"DELETE", "/api/members/" + u.ID}, {"POST", "/api/members/" + u.ID + "/subscription-link"}, {"POST", "/api/members/" + u.ID + "/telegram"}} {
		requireStatus(t, controllerRequest(t, h, spec.method, spec.path, "", nil), 401)
		requireStatus(t, controllerRequest(t, h, spec.method, spec.path, jwt, nil), 403)
	}
}

func TestMemberManagementRevokesSessionsAndDeletesProfilelessUser(t *testing.T) {
	a, h, adminToken := controllerFixture(t)
	ctx := context.Background()
	u := store.User{ID: "profileless", Username: "profileless", Role: "user", PasswordHash: "hash"}
	if err := a.DB.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	jwt, _ := a.Signer.Issue(u.ID, 0)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", jwt, nil), 200)
	path := "/api/members/" + u.ID
	requireStatus(t, controllerRequest(t, h, "PUT", path, adminToken, map[string]any{"row": map[string]any{"password": "new-password-2026", "recordVersion": 0}}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", jwt, nil), 401)
	profile, err := a.DB.GetRecord(ctx, "members", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = a.DB.UserByID(ctx, u.ID)
	jwt, _ = a.Signer.Issue(u.ID, u.TokenVersion)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", jwt, nil), 200)
	requireStatus(t, controllerRequest(t, h, "PUT", path, adminToken, map[string]any{"row": map[string]any{"status": "暂停", "recordVersion": profile.Version}}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", jwt, nil), 401)
	requireStatus(t, controllerRequest(t, h, "DELETE", path, adminToken, map[string]any{}), 400)
	requireStatus(t, controllerRequest(t, h, "DELETE", path, adminToken, map[string]any{"confirm": true}), 200)
	if _, err := a.DB.UserByID(ctx, u.ID); err != store.ErrNotFound {
		t.Fatal("user was not deleted", err)
	}
	u = store.User{ID: "no-profile", Username: "no-profile", Role: "user", PasswordHash: "hash"}
	if err := a.DB.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/members/"+u.ID, adminToken, map[string]any{"confirm": true}), 200)
	admin, _ := a.DB.UserByUsername(ctx, "test-admin")
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/members/"+admin.ID, adminToken, map[string]any{"confirm": true}), 409)
}

func TestMemberManagementLinksAndTelegram(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	h := a.Handler()
	admin, _ := a.DB.UserByID(ctx, "admin")
	jwt, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	endpoint := "/api/members/" + sub.OwnerID
	res := controllerRequest(t, h, "POST", endpoint+"/subscription-link", jwt, map[string]any{})
	requireStatus(t, res, 200)
	first := text(responseMap(t, res), "shortCode")
	if len(first) < 24 {
		t.Fatal("weak subscription credential")
	}
	res = controllerRequest(t, h, "POST", endpoint+"/subscription-link", jwt, map[string]any{})
	requireStatus(t, res, 200)
	if text(responseMap(t, res), "shortCode") != first {
		t.Fatal("copy rotated existing link")
	}
	requireStatus(t, controllerRequest(t, h, "POST", endpoint+"/subscription-link", jwt, map[string]any{"code": "short", "confirm": true}), 400)
	code := "user-code-2026-abcdefghijklmnop"
	requireStatus(t, controllerRequest(t, h, "POST", endpoint+"/subscription-link", jwt, map[string]any{"code": code}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", endpoint+"/subscription-link", jwt, map[string]any{"code": code, "confirm": true}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/merged-subscribe?token="+url.QueryEscape(first), "", nil), 404)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/merged-subscribe?token="+url.QueryEscape(code), "", nil), 200)
	other := store.User{ID: "other", Username: "other", Role: "user", PasswordHash: "hash"}
	if err := a.DB.CreateUser(ctx, other); err != nil {
		t.Fatal(err)
	}
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "other-sub", OwnerID: other.ID, Data: map[string]any{"planId": "plan"}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/members/other/subscription-link", jwt, map[string]any{"code": code, "confirm": true}), 409)
	binding := controllerRequest(t, h, "POST", endpoint+"/telegram", jwt, map[string]any{})
	requireStatus(t, binding, 200)
	command := text(responseMap(t, binding), "command")
	if _, err = a.telegramCommand(ctx, "1234567", command); err != nil {
		t.Fatal(err)
	}
	res = controllerRequest(t, h, "GET", "/api/members/management", jwt, nil)
	requireStatus(t, res, 200)
	var payload struct {
		Rows []map[string]any `json:"rows"`
	}
	if err = json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range payload.Rows {
		if text(row, "id") == sub.OwnerID {
			found = true
			if len(row["telegram"].([]any)) != 1 || len(row["subscriptions"].([]any)) != 1 || text(row, "shortCode") != code {
				t.Fatal("invalid user projection")
			}
		}
	}
	if !found {
		t.Fatal("member missing")
	}
	for _, secret := range []string{"password_hash", "credentialPassword", "credentialUUID", "tokenHash"} {
		if strings.Contains(res.Body.String(), secret) {
			t.Fatal("credentials leaked into list")
		}
	}
	requireStatus(t, controllerRequest(t, h, "POST", endpoint+"/telegram", jwt, map[string]any{"unbind": true}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", endpoint+"/telegram", jwt, map[string]any{"unbind": true, "confirm": true}), 200)
	bindings, err := a.DB.ListRecords(ctx, "_telegramBindings", sub.OwnerID)
	if err != nil || len(bindings) != 0 {
		t.Fatal("binding not removed", err)
	}
}
