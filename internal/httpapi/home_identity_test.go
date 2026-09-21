package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"testing"
	"time"
)

func TestHomePairingOneUseAndRotationGrace(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	ctx := context.Background()
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "endpoints", ID: "home", Data: map[string]any{"name": "fixture home", "status": "启用"}})
	created := controllerRequest(t, h, "POST", "/api/home/home/pairing", jwt, nil)
	requireStatus(t, created, 200)
	code := text(responseMap(t, created), "code")
	paired := controllerRequest(t, h, "POST", "/api/home/pair", "", map[string]any{"code": code})
	requireStatus(t, paired, 200)
	config := responseMap(t, paired)["config"].(map[string]any)
	old := text(config, "token")
	if len(old) < 32 || text(config, "role") != "speedtest" || text(config, "connection_mode") != "websocket" {
		t.Fatal("bad paired config")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/home/pair", "", map[string]any{"code": code}), 400)
	rotated := controllerRequest(t, h, "POST", "/api/home/home/rotate", jwt, nil)
	requireStatus(t, rotated, 202)
	cred, e := a.DB.GetRecord(ctx, "_homeCredentials", "home")
	if e != nil || text(cred.Data, "serverToken") == old || !homeTokenAccepted(cred, old, time.Now()) || homeTokenAccepted(cred, old, time.Now().Add(16*time.Minute)) {
		t.Fatal("old identity grace invalid")
	}
	tasks, e := a.DB.ListTasks(ctx, "home", 10)
	if e != nil || len(tasks) != 1 || tasks[0].Kind != "identity.rotate" {
		t.Fatal("rotation command missing")
	}
	var cmd agentwire.Command
	if e = json.Unmarshal(tasks[0].Input, &cmd); e != nil || text(cmd.Params, "token") != text(cred.Data, "serverToken") {
		t.Fatal("rotation command and identity disagree")
	}
	reply, e := a.acceptHomeReport(ctx, agentwire.Report{ServerID: "home", Token: old, Timestamp: time.Now().Unix()}, "WebSocket")
	if e != nil || len(reply.Commands) != 1 || reply.Commands[0].Action != "identity.rotate" {
		t.Fatal("old identity could not receive rotation")
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/home/home/rotate", jwt, nil), 409)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/home/home/pairing", "", nil), 401)
}
