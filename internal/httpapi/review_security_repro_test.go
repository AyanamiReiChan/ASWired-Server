package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestReviewAPITokenCannotMintBrowserJWT(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	u, _ := a.DB.UserByUsername(ctx, "test-admin")
	issued, e := a.createAPIToken(ctx, u, map[string]any{"scopes": []string{"read", "write"}})
	if e != nil {
		t.Fatal(e)
	}
	token := text(issued, "token")
	requireStatus(t, controllerRequest(t, h, "GET", "/api/account/security", token, nil), 403)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/auth/callback/authorize", token, nil), 403)
	start := controllerRequest(t, h, "POST", "/api/auth/qr/start", "", nil)
	requireStatus(t, start, 200)
	state := responseMap(t, start)
	qr, _ := url.Parse(text(state, "qrURL"))
	approved := controllerRequest(t, h, "POST", "/api/auth/qr/approve", token, map[string]any{"code": qr.Query().Get("code"), "confirmed": true, "verificationCode": state["verificationCode"]})
	if approved.Code == 403 {
		return
	}
	requireStatus(t, approved, 200)
	poll := controllerRequest(t, h, "POST", "/api/auth/qr/poll", "", map[string]any{"requestId": state["requestId"], "pollSecret": state["pollSecret"]})
	requireStatus(t, poll, 200)
	browserJWT := text(responseMap(t, poll), "token")
	account := controllerRequest(t, h, "GET", "/api/account/security", browserJWT, nil)
	if account.Code == 200 {
		t.Fatal("scoped API token minted a browser JWT and bypassed session_required")
	}
}
func TestReviewHomeCannotPublishAnotherEndpointResult(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	token := strings.Repeat("home-token", 5)
	for _, r := range []store.Record{{Collection: "endpoints", ID: "attacker-home", Data: map[string]any{"name": "home"}}, {Collection: "_homeCredentials", ID: "attacker-home", Data: map[string]any{"serverToken": token}}} {
		if _, e := a.DB.SaveRecord(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	task, e := a.DB.SaveTask(ctx, store.Task{ID: "other-task", ServerID: "other-home", ActorID: "victim", Kind: "speedtest.run", Status: "running"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = a.acceptHomeReport(ctx, agentwire.Report{ServerID: "attacker-home", Token: token, Results: []agentwire.Result{{ID: task.ID, Status: "success", Data: map[string]any{"download_mbps": 999}}}}, "WebSocket")
	if e != nil {
		t.Fatal(e)
	}
	if forged, e := a.DB.GetRecord(ctx, "speedtests", task.ID); e == nil {
		t.Fatalf("foreign task result was published for owner %s", forged.OwnerID)
	}
}
func TestReviewDisabledServerMustNotClaimWork(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	token := strings.Repeat("server-token", 5)
	for _, r := range []store.Record{{Collection: "servers", ID: "off", Data: map[string]any{"name": "disabled server", "status": "禁用", "address": "127.0.0.1"}}, {Collection: "_agentCredentials", ID: "off", Data: map[string]any{"serverToken": token}}} {
		if _, e := a.DB.SaveRecord(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	command, _ := json.Marshal(agentwire.Command{ID: "queued", Action: "core.restart"})
	if _, e := a.DB.SaveTask(ctx, store.Task{ID: "queued", ServerID: "off", Kind: "core.restart", Status: "queued", Input: command}); e != nil {
		t.Fatal(e)
	}
	reply, e := a.acceptReport(ctx, agentwire.Report{ServerID: "off", Token: token, Timestamp: time.Now().Unix(), Mode: "embedded"}, "WebSocket")
	if e == nil && len(reply.Commands) > 0 {
		t.Fatal("disabled server authenticated and received a queued core.restart")
	}
}
