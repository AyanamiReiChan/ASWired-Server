package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestKomariSessionRevocation(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	a.Config.KomariPublicURL = "https://probe.example.test"
	a.Config.KomariBridgeSecret = strings.Repeat("s", 32)
	u := store.User{ID: "probe", Username: "probe", Role: "admin", PasswordHash: "fixture", TokenVersion: 1}
	if _, err := a.DB.SaveMemberRecord(ctx, u, store.Record{Collection: "members", ID: u.ID, Data: map[string]any{"application": "aswired"}}, false); err != nil {
		t.Fatal(err)
	}
	issueSession := func() string {
		t.Helper()
		out := httptest.NewRecorder()
		a.issueKomari(out, u)
		requireStatus(t, out, 200)
		redeemed := bridgeRequest(t, h, a.Config.KomariBridgeSecret, "redeem", map[string]any{"ticket": text(responseMap(t, out), "ticket")})
		requireStatus(t, redeemed, 200)
		return text(responseMap(t, redeemed), "session")
	}
	session := issueSession()
	logout := bridgeRequest(t, h, a.Config.KomariBridgeSecret, "introspect", map[string]any{"session": session, "logout": true})
	requireStatus(t, logout, 200)
	requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "introspect", map[string]any{"session": session}), 401)
	u, _ = a.DB.UserByID(ctx, u.ID)
	session = issueSession()
	// Password changes increment TokenVersion; outstanding tickets must also die.
	ticketOut := httptest.NewRecorder()
	a.issueKomari(ticketOut, u)
	u.TokenVersion++
	if err := a.DB.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "introspect", map[string]any{"session": session}), 401)
	requireStatus(t, bridgeRequest(t, h, a.Config.KomariBridgeSecret, "redeem", map[string]any{"ticket": text(responseMap(t, ticketOut), "ticket")}), 401)
}
