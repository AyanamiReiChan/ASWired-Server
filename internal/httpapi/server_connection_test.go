package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestServerCreationOnlyAcceptsNativeConnections(t *testing.T) {
	a, h, token := controllerFixture(t)
	for _, fields := range []map[string]any{
		{"connection": "legacy-adapter"},
		{"connection": "unsupported", "managementMode": "agent"},
		{"managementMode": "legacy-adapter"},
		{"xuiURL": "https://retired.example.test", "xuiToken": "retired-secret"},
		{"xuiURL": "invalid"},
	} {
		fields["name"] = "Unsupported"
		fields["address"] = "127.0.0.1"
		requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": fields}), http.StatusBadRequest)
	}
	servers, err := a.DB.ListRecords(context.Background(), "servers", "")
	if err != nil || len(servers) != 0 {
		t.Fatalf("rejected server persisted: %v %d", err, len(servers))
	}
	for _, connection := range []string{"", "websocket", "WebSocket", "auto", "自动", "HTTP", "Pull", "轮询"} {
		fields := map[string]any{"name": "Agent", "address": "127.0.0.1", "connection": connection}
		response := controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": fields})
		requireStatus(t, response, http.StatusOK)
		row := responseMap(t, response)["row"].(map[string]any)
		if !nativeServerConnection(text(row, "connection")) || text(row, "managementMode") != "agent" {
			t.Fatal("native connection missing")
		}
		enrollment := controllerRequest(t, h, "GET", "/api/servers/"+text(row, "id")+"/enrollment", token, nil)
		requireStatus(t, enrollment, http.StatusOK)
		cfg := responseMap(t, enrollment)["config"].(map[string]any)
		if cfg["connection_mode"] != serverConnectionMode(store.Record{Data: row}) {
			t.Fatal("installer lost connection selection")
		}
	}
}

func TestLegacyServerIsProtectedUntilExplicitAgentSelection(t *testing.T) {
	for _, connection := range []string{"WebSocket"} {
		t.Run(connection, func(t *testing.T) {
			a, h, token := controllerFixture(t)
			ctx := context.Background()
			data := map[string]any{"name": "Existing server", "address": "127.0.0.1", "connection": "legacy-adapter", "managementMode": "legacy", "xuiURL": "https://user:secret@retired.example.test", "xuiToken": "retired-secret", "xuiCACertificatePEM": "retired-cert"}
			server, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "legacy", Data: data})
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_agentCredentials", ID: server.ID, Data: map[string]any{"serverToken": "server-token", "agentToken": "agent-token"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/collections/servers/" + server.ID, "/api/collections/servers", "/api/state"} {
				response := controllerRequest(t, h, "GET", path, token, nil)
				requireStatus(t, response, http.StatusOK)
				if strings.Contains(response.Body.String(), "xui") || strings.Contains(response.Body.String(), "retired-secret") || strings.Contains(response.Body.String(), "user:secret") || !strings.Contains(response.Body.String(), "需重新接入") {
					t.Fatalf("unsafe legacy response: %s", response.Body)
				}
			}
			stored, err := a.DB.GetRecord(ctx, "servers", server.ID)
			if err != nil || stored.Version != server.Version || text(stored.Data, "connection") != "legacy-adapter" || text(stored.Data, "xuiToken") != "retired-secret" {
				t.Fatal("reading changed legacy record")
			}
			requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/"+server.ID+"/enrollment", token, nil), http.StatusConflict)
			report := agentwire.Report{ServerID: server.ID, Token: "server-token", Timestamp: time.Now().Unix(), Mode: "embedded", Observation: map[string]any{"cpu_percent": 75}}
			if _, err = a.acceptReport(ctx, report, "WebSocket"); err == nil {
				t.Fatal("legacy Agent report accepted")
			}
			if _, err = a.DB.GetRecord(ctx, "_observations", server.ID); err == nil {
				t.Fatal("legacy observation persisted")
			}
			if _, err = a.queue(ctx, store.User{ID: "admin", Role: "admin"}, server.ID, "core.status", nil); err == nil {
				t.Fatal("legacy command queued")
			}
			for _, patch := range []map[string]any{{"name": "Renamed"}, {"name": "Renamed", "connection": "", "managementMode": "agent"}} {
				requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/servers/"+server.ID, token, map[string]any{"row": patch}), http.StatusBadRequest)
			}
			task := storedAgentTask(t, a, server.ID, "old-normal", "core.status", "core.status")
			if a.permitDispatch(ctx, task) {
				t.Fatal("legacy task dispatched")
			}
			updated := controllerRequest(t, h, "PUT", "/api/collections/servers/"+server.ID, token, map[string]any{"row": map[string]any{"name": "Agent", "connection": connection}})
			requireStatus(t, updated, http.StatusOK)
			stored, err = a.DB.GetRecord(ctx, "servers", server.ID)
			if err != nil || !nativeServer(stored) || text(stored.Data, "managementMode") != "agent" || text(stored.Data, "xuiToken") != "retired-secret" {
				t.Fatal("explicit Agent selection failed or legacy data lost")
			}
			requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/"+server.ID+"/enrollment", token, nil), http.StatusOK)
			retired := storedAgentTask(t, a, server.ID, "retired", "xui.sync", "xui.sync")
			mismatch := storedAgentTask(t, a, server.ID, "retired-payload", "core.status", "xui.sync")
			if a.permitDispatch(ctx, retired) || a.permitDispatch(ctx, mismatch) {
				t.Fatal("retired action dispatched after Agent selection")
			}
			queued, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, server.ID, "core.status", nil)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := a.acceptReport(ctx, report, "WebSocket")
			if err != nil || len(reply.Commands) != 1 || reply.Commands[0].ID != queued.ID {
				t.Fatalf("native commands did not recover: %v %+v", err, reply.Commands)
			}
			tasks, err := a.DB.ListTasks(ctx, server.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			for _, task := range tasks {
				if task.ID == queued.ID {
					continue
				}
				if task.Status != "failed" {
					t.Fatalf("blocked task %s remains %s", task.ID, task.Status)
				}
			}
		})
	}
}

func storedAgentTask(t *testing.T, a *App, serverID, id, kind, action string) store.Task {
	t.Helper()
	raw, err := json.Marshal(agentwire.Command{ID: id, Action: action})
	if err != nil {
		t.Fatal(err)
	}
	task, err := a.DB.SaveTask(context.Background(), store.Task{ID: id, ServerID: serverID, Kind: kind, Status: "queued", Input: raw, CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestRetiredActionsAreAbsentAndCannotBeQueued(t *testing.T) {
	a, h, token := controllerFixture(t)
	response := controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": map[string]any{"name": "Agent", "address": "127.0.0.1"}})
	requireStatus(t, response, http.StatusOK)
	id := text(responseMap(t, response)["row"].(map[string]any), "id")
	for _, action := range []string{"xui.test", "xui.sync", "xui.inbound.apply", "xui.template.get", "xui.template.apply"} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": action, "targetId": id}), http.StatusNotImplemented)
		if _, err := a.queue(context.Background(), store.User{ID: "admin", Role: "admin"}, id, action, nil); err == nil {
			t.Fatalf("retired action accepted: %s", action)
		}
	}
	for _, tool := range mcpCatalog() {
		if retiredAgentAction(tool.Action) {
			t.Fatalf("retired MCP tool: %s", tool.Name)
		}
	}
	caps, _ := json.Marshal(capabilityMap())
	if strings.Contains(string(caps), "panel-api") {
		t.Fatal("retired capability advertised")
	}
	tasks, err := a.DB.ListTasks(context.Background(), id, 100)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("retired action task persisted: %v %d", err, len(tasks))
	}
}

func TestUnsupportedServerCannotAlterExistingTraffic(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	key := "user>>>" + text(sub.Data, "credentialEmail") + ">>>traffic>>>uplink"
	at := time.Now().UnixMilli()
	sample := func(value int64) {
		a.accountStats(ctx, "server", map[string]any{"generation": "same-core", "timestamp": at, "reset": false, "counters": map[string]any{key: value}})
		at++
	}
	sample(100)
	server, err := a.DB.GetRecord(ctx, "servers", "server")
	if err != nil {
		t.Fatal(err)
	}
	server.Data["connection"] = "legacy-adapter"
	server, err = a.DB.SaveRecord(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	sample(900)
	var raw int64
	if err := a.DB.DB().QueryRowContext(ctx, `SELECT SUM(raw_bytes) FROM traffic_ledger WHERE server_id='server'`).Scan(&raw); err != nil || raw != 100 {
		t.Fatalf("unsupported sample altered ledger: %d %v", raw, err)
	}
	var cursor int64
	if err := a.DB.DB().QueryRowContext(ctx, `SELECT last_value FROM traffic_cursors WHERE server_id='server'`).Scan(&cursor); err != nil || cursor != 100 {
		t.Fatalf("unsupported sample altered cursor: %d %v", cursor, err)
	}
	server.Data["connection"] = "WebSocket"
	if _, err = a.DB.SaveRecord(ctx, server); err != nil {
		t.Fatal(err)
	}
	sample(140)
	if err := a.DB.DB().QueryRowContext(ctx, `SELECT SUM(raw_bytes) FROM traffic_ledger WHERE server_id='server'`).Scan(&raw); err != nil || raw != 140 {
		t.Fatalf("Agent traffic did not resume correctly: %d %v", raw, err)
	}
}

func TestLegacyServerCannotClearOwnershipWithoutChoosingAgent(t *testing.T) {
	for _, legacy := range []map[string]any{
		{"connection": "legacy-adapter"},
		{"managementMode": "legacy-adapter"},
		{"xuiURL": "retired-address"},
	} {
		a, h, token := controllerFixture(t)
		ctx := context.Background()
		legacy["name"] = "Existing server"
		legacy["address"] = "127.0.0.1"
		before, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "legacy", Data: legacy})
		if err != nil {
			t.Fatal(err)
		}
		for _, patch := range []map[string]any{
			{"name": "Renamed"},
			{"name": "Renamed", "connection": ""},
			{"name": "Renamed", "connection": "", "managementMode": "agent", "xuiURL": ""},
			{"name": "Renamed", "connection": "unsupported"},
		} {
			response := controllerRequest(t, h, "PUT", "/api/collections/servers/legacy", token, map[string]any{"row": patch})
			requireStatus(t, response, http.StatusBadRequest)
			after, err := a.DB.GetRecord(ctx, "servers", "legacy")
			if err != nil || after.Version != before.Version || nativeServer(after) {
				t.Fatal("clearing ownership implicitly converted legacy server")
			}
		}
		response := controllerRequest(t, h, "PUT", "/api/collections/servers/legacy", token, map[string]any{"row": map[string]any{"name": "Agent", "connection": "WebSocket"}})
		requireStatus(t, response, http.StatusOK)
	}
}
