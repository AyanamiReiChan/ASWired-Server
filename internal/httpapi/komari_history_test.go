package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestKomariHistoryUsesBoundNodeAndPreservesPublicPrivacy(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	stamp := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/rpc2" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("wrong Komari endpoint/auth")
		}
		var call struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			t.Error(err)
		}
		if call.Method != "common:getRecords" || text(call.Params, "uuid") != "bound-node" || number(call.Params, "maxCount") != 4000 || number(call.Params, "hours") != 1 {
			t.Error("unbounded or incorrect query", call)
		}
		var result any
		if text(call.Params, "type") == "ping" {
			result = map[string]any{"tasks": []any{map[string]any{"id": 9, "type": "icmp", "name": "private target"}}, "records": []any{map[string]any{"client": "bound-node", "task_id": 9, "time": stamp, "value": 12}, map[string]any{"client": "bound-node", "task_id": 9, "time": stamp, "value": -1}, map[string]any{"client": "other-node", "task_id": 9, "time": stamp, "value": 9000}}}
		} else {
			result = map[string]any{"records": map[string]any{"bound-node": []any{map[string]any{"client": "bound-node", "time": stamp, "cpu": 25, "ram": 500, "ram_total": 1000, "net_total_up": 123, "token": "private-token", "ipv4": "192.0.2.9"}}, "other-node": []any{map[string]any{"time": stamp, "cpu": 99}}}}
		}
		respond(w, 200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer upstream.Close()
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": upstream.URL, "probeApiKey": "test-key", "probePublicEnabled": true, "showCPU": false, "showNetworkQuality": true, "showTraffic": false})
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"public": true, "komariUUID": "bound-node"}})
	if err != nil {
		t.Fatal(err)
	}
	response := controllerRequest(t, h, "GET", "/api/public/probe-series?server=0&range=1h", "", nil)
	requireStatus(t, response, 200)
	for _, secret := range []string{"cpu_pct", "cumulative_up", "private-token", "192.0.2.9", "bound-node", "other-node"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("public history leaked", secret)
		}
	}
	if !strings.Contains(response.Body.String(), "mem_used") {
		t.Fatal("Komari history not mapped")
	}
	response = controllerRequest(t, h, "GET", "/api/public/probe-series?server=0&metric=network&target=0", "", nil)
	requireStatus(t, response, 200)
	series := responseMap(t, response)["series"].(map[string]any)
	for key, want := range map[string]float64{"latency_ms": 12, "failure_percent": 50} {
		points, ok := series[key].([]any)
		if !ok || len(points) != 1 || number(points[0].(map[string]any), "value") != want {
			t.Fatal("wrong ping aggregation", series)
		}
	}
	if requests != 2 {
		t.Fatal(requests)
	}
	tasks, err := a.DB.ListTasks(ctx, "server", 10)
	if err != nil || len(tasks) != 0 {
		t.Fatal("history dispatched Agent work", err)
	}
}
