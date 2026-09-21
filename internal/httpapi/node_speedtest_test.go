package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"testing"
	"time"
)

func TestNodeSpeedtestBudgetAndPersistedFailure(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "node", Data: realityClientFixtureData()})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "endpoints", ID: "home", Data: map[string]any{"name": "Home", "status": "启用"}})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_homeCredentials", ID: "home", Data: map[string]any{"serverToken": "fixture-token-012345678901234567890123456789"}})
	body := map[string]any{"endpointId": "home", "duration": 30, "parallel": 64, "downloadBytes": 1 << 20, "downloadURL": "https://example.test/download", "ipCheckURL": "https://example.test/ip"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/node/speedtest", token, body), 400)
	report := agentwire.Report{ServerID: "home", Token: "fixture-token-012345678901234567890123456789", Capabilities: map[string]bool{"speedtest_bounded": true}, Observation: map[string]any{"source_mode": "controller", "platform": "linux"}}
	if _, err := a.acceptHomeReport(ctx, report, "WebSocket"); err != nil {
		t.Fatal(err)
	}
	response := controllerRequest(t, h, "POST", "/api/nodes/node/speedtest", token, body)
	requireStatus(t, response, 202)
	id := text(responseMap(t, response)["task"].(map[string]any), "id")
	task, _ := a.DB.GetTask(ctx, id)
	var cmd agentwire.Command
	_ = json.Unmarshal(task.Input, &cmd)
	if number(cmd.Params, "parallel") != 64 || number(cmd.Params, "download_bytes") != 1<<20 {
		t.Fatal("lost measurement settings")
	}
	record, err := a.DB.GetRecord(ctx, "speedtests", id)
	if err != nil || text(record.Data, "status") != "queued" {
		t.Fatal("missing queued history")
	}
	if _, err = a.acceptHomeReport(ctx, report, "WebSocket"); err != nil {
		t.Fatal(err)
	}
	report.Results = []agentwire.Result{{ID: id, Status: "failed", Error: "proxy unavailable", Data: map[string]any{"download_bytes": 123}}}
	if _, err = a.acceptHomeReport(ctx, report, "WebSocket"); err != nil {
		t.Fatal(err)
	}
	record, err = a.DB.GetRecord(ctx, "speedtests", id)
	if err != nil || text(record.Data, "status") != "failed" || text(record.Data, "error") != "proxy unavailable" || number(record.Data, "download_bytes") != 123 {
		t.Fatalf("lost failed history: %v %v", record, err)
	}
	body["downloadBytes"] = 2 << 20
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/node/speedtest", token, body), 400)
	a.mu.Lock()
	a.peers["home"].LastSeen = time.Now().Add(-time.Minute)
	a.mu.Unlock()
	body["downloadBytes"] = 1 << 20
	requireStatus(t, controllerRequest(t, h, "POST", "/api/nodes/node/speedtest", token, body), 400)
}
