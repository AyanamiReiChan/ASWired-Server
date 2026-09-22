package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestKomariUsesWorkspaceAdministrator(t *testing.T) {
	a, h, token := controllerFixture(t)
	a.Config.KomariPublicURL = "https://probe.example.test"
	a.Config.KomariBridgeSecret = strings.Repeat("s", 32)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/komari/login", "", nil), 401)
	issued := controllerRequest(t, h, "POST", "/api/komari/login", token, nil)
	requireStatus(t, issued, 200)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", token, nil), 200)
	redeemed := bridgeRequest(t, h, a.Config.KomariBridgeSecret, "redeem", map[string]any{"ticket": text(responseMap(t, issued), "ticket")})
	requireStatus(t, redeemed, 200)
	identity := responseMap(t, redeemed)
	if identity["username"] != "test-admin" {
		t.Fatal("Komari did not inherit the workspace administrator")
	}
	session := text(identity, "session")
	requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "introspect", map[string]any{"session": session, "logout": true}), 200)
	// Logging out from Komari also revokes the shared ASWired login.
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state", token, nil), 401)
}

func TestKomariDeniesMembersLegacyAccountsAndUnapprovedAdministrators(t *testing.T) {
	for _, fixture := range []struct{ name, role, application string }{
		{"member", "user", "aswired"}, {"legacy", "user", "komari"},
		{"legacy-admin", "admin", "komari"}, {"restricted-admin", "admin", "aswired"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			a, h, adminToken := controllerFixture(t)
			a.Config.KomariPublicURL = "https://probe.example.test"
			a.Config.KomariBridgeSecret = strings.Repeat("s", 32)
			a.Config.AdminUsernames = []string{"test-admin"}
			hash, err := auth.HashPassword("test-password-2026")
			if err != nil {
				t.Fatal(err)
			}
			u := store.User{ID: fixture.name, Username: fixture.name, Role: fixture.role, PasswordHash: hash, TokenVersion: 1}
			_, err = a.DB.SaveMemberRecord(context.Background(), u, store.Record{Collection: "members", ID: u.ID, Data: map[string]any{"application": fixture.application}}, false)
			if err != nil {
				t.Fatal(err)
			}
			token, _ := a.Signer.Issue(u.ID, u.TokenVersion)
			requireStatus(t, controllerRequest(t, h, "POST", "/api/komari/login", token, nil), 403)
			out := httptest.NewRecorder()
			a.issueKomari(out, u)
			requireStatus(t, out, 403)
			if fixture.application == "komari" {
				requireStatus(t, controllerRequest(t, h, "POST", "/api/login", "", map[string]any{"username": u.Username, "password": "test-password-2026"}), 403)
			}
			response := controllerRequest(t, h, "POST", "/api/collections/members", adminToken, map[string]any{"row": map[string]any{"id": "new-probe", "username": "new-probe", "name": "Probe", "password": "test-password-2026", "application": "komari", "role": "成员"}})
			requireStatus(t, response, 400)
			if _, err := a.DB.UserByUsername(context.Background(), "new-probe"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("rejected account persisted", err)
			}
		})
	}
}

func TestKomariSessionsRecheckAdministratorPermissions(t *testing.T) {
	for _, change := range []string{"downgrade", "disable", "password", "allowlist", "logout"} {
		t.Run(change, func(t *testing.T) {
			a, h, token := controllerFixture(t)
			a.Config.KomariPublicURL = "https://probe.example.test"
			a.Config.KomariBridgeSecret = strings.Repeat("s", 32)
			issue := func() string {
				out := controllerRequest(t, h, "POST", "/api/komari/login", token, nil)
				requireStatus(t, out, 200)
				return text(responseMap(t, out), "ticket")
			}
			redeemed := bridgeRequest(t, h, a.Config.KomariBridgeSecret, "redeem", map[string]any{"ticket": issue()})
			requireStatus(t, redeemed, 200)
			session := text(responseMap(t, redeemed), "session")
			ticket := issue()
			u, err := a.DB.UserByUsername(context.Background(), "test-admin")
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "downgrade":
				u.Role = "user"
			case "disable":
				u.Disabled = true
			case "password":
				u.TokenVersion++
			case "allowlist":
				a.Config.AdminUsernames = []string{"someone-else"}
			case "logout":
				requireStatus(t, controllerRequest(t, h, "POST", "/api/logout", token, nil), 200)
			}
			if change != "logout" {
				if err = a.DB.UpdateUser(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			}
			requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "introspect", map[string]any{"session": session}), 401)
			requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "redeem", map[string]any{"ticket": ticket}), 401)
		})
	}
}
