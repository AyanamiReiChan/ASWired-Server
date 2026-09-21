package httpapi

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestMCPCatalogScopesAndDeletionConfirmation(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	seen := map[string]bool{}
	for _, spec := range mcpCatalog() {
		if seen[spec.Name] {
			t.Fatalf("duplicate tool %s", spec.Name)
		}
		seen[spec.Name] = true
	}
	if len(seen) < 100 {
		t.Fatal("incomplete catalog")
	}
	result := controllerRequest(t, h, "POST", "/api/actions", jwt, map[string]any{"action": "token.create", "params": map[string]any{"name": "test MCP", "scopes": []string{"read", "write"}}})
	requireStatus(t, result, 200)
	token := text(responseMap(t, result), "token")
	ctx := context.Background()
	_, e := a.DB.SaveRecord(ctx, store.Record{Collection: "announcements", ID: "notice", Data: map[string]any{"name": "test"}})
	if e != nil {
		t.Fatal(e)
	}
	request := func(confirm bool) string {
		args := map[string]any{"id": "notice"}
		if confirm {
			args["confirm"] = true
		}
		r := controllerRequest(t, h, "POST", "/mcp", token, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "announcements_delete", "arguments": args}})
		requireStatus(t, r, 200)
		return r.Body.String()
	}
	if !strings.Contains(request(false), "confirm=true") {
		t.Fatal("delete bypassed confirmation")
	}
	if _, e = a.DB.GetRecord(ctx, "announcements", "notice"); e != nil {
		t.Fatal("unconfirmed delete changed data")
	}
	if strings.Contains(request(true), `"isError":true`) {
		t.Fatal("confirmed delete failed")
	}
	if _, e = a.DB.GetRecord(ctx, "announcements", "notice"); e == nil {
		t.Fatal("delete not executed")
	}
}
func telegramFixtureInit(token string, id int64, when time.Time) string {
	values := url.Values{"auth_date": {fmt.Sprint(when.Unix())}, "query_id": {"fixture"}, "user": {fmt.Sprintf(`{"id":%d,"first_name":"Fixture"}`, id)}}
	keys := []string{}
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := []string{}
	for _, k := range keys {
		lines = append(lines, k+"="+values.Get(k))
	}
	values.Set("hash", hex.EncodeToString(hmacSHA256(hmacSHA256([]byte("WebAppData"), token), strings.Join(lines, "\n"))))
	return values.Encode()
}
func TestTelegramBindingSignatureAndRoles(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	ctx := context.Background()
	token := "fixture-bot-secret"
	if e := a.DB.SetSetting(ctx, "settings", map[string]any{"telegramToken": token, "telegramMiniAppEnabled": true, "telegramWebhookSecret": "webhook-test"}); e != nil {
		t.Fatal(e)
	}
	bind := controllerRequest(t, h, "POST", "/api/account/telegram", jwt, map[string]any{})
	requireStatus(t, bind, 200)
	code := text(responseMap(t, bind), "code")
	if _, e := a.telegramCommand(ctx, "42", "/bind "+code); e != nil {
		t.Fatal(e)
	}
	if _, e := a.telegramCommand(ctx, "43", "/bind "+code); e == nil {
		t.Fatal("bind code replay accepted")
	}
	init := telegramFixtureInit(token, 42, time.Now())
	signed := controllerRequest(t, h, "POST", "/api/telegram/miniapp", "", map[string]any{"initData": init})
	requireStatus(t, signed, 200)
	claims, e := a.Signer.Parse(text(responseMap(t, signed), "token"))
	if e != nil {
		t.Fatal(e)
	}
	user, _ := a.DB.UserByID(ctx, claims.Subject)
	if user.Username != "test-admin" {
		t.Fatal("JWT not linked to bound account")
	}
	if _, e := verifyTelegramInit(init+"&user=bad", token, time.Now()); e == nil {
		t.Fatal("duplicate signed field accepted")
	}
	if _, e := verifyTelegramInit(init, "wrong-secret", time.Now()); e == nil {
		t.Fatal("wrong signature accepted")
	}
	if _, e := verifyTelegramInit(telegramFixtureInit(token, 42, time.Now().Add(-6*time.Minute)), token, time.Now()); e == nil {
		t.Fatal("expired login accepted")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/telegram/webhook", "", map[string]any{}), 403)
	user.Role = "user"
	if e = a.DB.UpdateUser(ctx, user); e != nil {
		t.Fatal(e)
	}
	if _, e = a.telegramCommand(ctx, "42", "/servers"); e == nil {
		t.Fatal("member can inspect all servers")
	}
	user, _ = a.DB.UserByID(ctx, user.ID)
	user.Disabled = true
	if e = a.DB.UpdateUser(ctx, user); e != nil {
		t.Fatal(e)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/telegram/miniapp", "", map[string]any{"initData": init}), 403)
}
func TestProbeSourceSelectionDoesNotFallback(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	server := store.Record{Collection: "servers", ID: "server-probe", Data: map[string]any{"name": "public test", "public": true, "probeSource": "komari", "komariUUID": "uuid", "privateKey": "must-not-leak"}}
	_, _ = a.DB.SaveRecord(ctx, server)
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probePublicEnabled": true, "probeBaseUrl": "http://komari.test", "customCSS": "body{font-size:16px}", "telegramToken": "private-value"})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: server.ID, Data: map[string]any{"cpu_percent": 99}})
	a.peers[server.ID] = &peer{LastSeen: time.Now()}
	response := controllerRequest(t, h, "GET", "/api/public/probe-servers", "", nil)
	requireStatus(t, response, 200)
	if strings.Contains(response.Body.String(), "cpu_pct") || strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatal("missing Komari fell back or leaked")
	}
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_komariObservations", ID: server.ID, Data: map[string]any{"komari_uuid": "uuid", "komari_base_url": "http://komari.test", "cpu_percent": 13, "sampled_at": time.Now().UTC().Format(time.RFC3339Nano), "online": true}})
	response = controllerRequest(t, h, "GET", "/api/public/probe-servers", "", nil)
	if !strings.Contains(response.Body.String(), `"cpu_pct":13`) || !strings.Contains(response.Body.String(), `"online":true`) {
		t.Fatal("selected Komari sample not projected")
	}
	response = controllerRequest(t, h, "GET", "/api/public/appearance", "", nil)
	if strings.Contains(response.Body.String(), "private-value") || len(responseMap(t, response)) != 2 {
		t.Fatal("appearance returned extra settings")
	}
}
