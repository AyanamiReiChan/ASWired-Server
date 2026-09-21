package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"net/http"
	"testing"
	"time"
)

func TestPullEncryptedTasksResultsAndReplay(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	response := controllerRequest(t, h, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "pull-node", "name": "Pull", "address": "127.0.0.1", "connection": "轮询"}})
	requireStatus(t, response, 200)
	creds, _ := a.DB.GetRecord(ctx, "_agentCredentials", "pull-node")
	task, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, "pull-node", "core.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	report := agentwire.Report{ServerID: "pull-node", Token: text(creds.Data, "serverToken"), Mode: "embedded", ConnectionMode: "pull", Timestamp: time.Now().Unix(), Capabilities: map[string]bool{"connection_modes": true}}
	exchange := func(report agentwire.Report) agentwire.Reply {
		t.Helper()
		channel, err := agentwire.NewClient(a.MasterPublic)
		if err != nil {
			t.Fatal(err)
		}
		packet, err := channel.Seal(report)
		if err != nil {
			t.Fatal(err)
		}
		hello := agentwire.Hello{PublicKey: channel.PublicKey(), Packet: packet}
		response := controllerRequest(t, h, "POST", "/api/agent/pull", "", hello)
		requireStatus(t, response, 200)
		var incoming agentwire.Packet
		if err := json.Unmarshal(response.Body.Bytes(), &incoming); err != nil {
			t.Fatal(err)
		}
		var reply agentwire.Reply
		if err := channel.Open(incoming, &reply); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/agent/pull", "", hello), http.StatusConflict)
		return reply
	}
	reply := exchange(report)
	if reply.Error != "" || len(reply.Commands) != 1 || reply.Commands[0].ID != task.ID || reply.ConnectionMode != "pull" {
		t.Fatalf("unexpected reply: %+v", reply)
	}
	report.Results = []agentwire.Result{{ID: task.ID, Status: "success", Data: map[string]any{"ok": true}}}
	reply = exchange(report)
	finished, err := a.DB.GetTask(ctx, task.ID)
	if err != nil || finished.Status != "success" || len(reply.Commands) != 0 {
		t.Fatalf("result not acknowledged: %+v %v", finished, err)
	}
	report.Token = "wrong-token"
	if exchange(report).Error == "" {
		t.Fatal("invalid identity accepted")
	}
	report.Token = text(creds.Data, "serverToken")
	report.Timestamp = time.Now().Add(-2 * time.Minute).Unix()
	if exchange(report).Error == "" {
		t.Fatal("stale report accepted")
	}
}

func TestConfiguredModeIsNotOverwrittenByActiveTransport(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	response := controllerRequest(t, h, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "auto-node", "name": "Auto", "address": "127.0.0.1", "connection": "自动"}})
	requireStatus(t, response, 200)
	creds, _ := a.DB.GetRecord(ctx, "_agentCredentials", "auto-node")
	report := agentwire.Report{ServerID: "auto-node", Token: text(creds.Data, "serverToken"), Mode: "embedded", ConnectionMode: "auto", Timestamp: time.Now().Unix(), Capabilities: map[string]bool{"connection_modes": true}}
	if _, err := a.acceptReport(ctx, report, "WebSocket"); err != nil {
		t.Fatal(err)
	}
	response = controllerRequest(t, h, "GET", "/api/collections/servers", admin, nil)
	requireStatus(t, response, 200)
	var data struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 || data.Rows[0]["connection"] != "自动" || data.Rows[0]["activeConnection"] != "WebSocket" {
		t.Fatalf("configured mode lost: %s", response.Body)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/servers/auto-node", admin, map[string]any{"row": map[string]any{"connection": "HTTP"}}), 200)
	task, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, "auto-node", "core.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := a.acceptReport(ctx, report, "WebSocket")
	if err != nil || reply.ConnectionMode != "http" || len(reply.Commands) != 0 {
		t.Fatalf("work dispatched during switch: %+v %v", reply, err)
	}
	pending, _ := a.DB.GetTask(ctx, task.ID)
	if pending.Status != "queued" {
		t.Fatal("switch consumed queued task")
	}
}
