package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestKomariIsOnlyProbeIncludingLegacySettings(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	for _, legacy := range []string{"", "native", "Komari"} {
		if err := a.DB.SetSetting(ctx, "settings", map[string]any{"probeProvider": legacy, "komariAutoSync": false}); err != nil {
			t.Fatal(err)
		}
		response := controllerRequest(t, h, "GET", "/api/settings", token, nil)
		requireStatus(t, response, 200)
		settings := responseMap(t, response)["settings"].(map[string]any)
		if text(settings, "probeProvider") != "Komari" || !boolean(settings, "komariAutoSync") {
			t.Fatal(settings)
		}
		response = controllerRequest(t, h, "PUT", "/api/settings", token, map[string]any{"settings": map[string]any{"probeProvider": legacy, "komariAutoSync": false}})
		requireStatus(t, response, 200)
		if err := a.DB.GetSetting(ctx, "settings", &settings); err != nil {
			t.Fatal(err)
		}
		if text(settings, "probeProvider") != "Komari" || !boolean(settings, "komariAutoSync") {
			t.Fatal(settings)
		}
	}
}

func TestKomariBindingAndLegacyAgentIsolation(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	response := controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": map[string]any{"name": "Host", "address": "127.0.0.1", "probeSource": "native", "public": true}})
	requireStatus(t, response, 200)
	row := responseMap(t, response)["row"].(map[string]any)
	id := text(row, "id")
	if text(row, "probeSource") != "komari" {
		t.Fatal(row)
	}
	credentials, _ := a.DB.GetRecord(ctx, "_agentCredentials", id)
	_, err := a.acceptReport(ctx, agentwire.Report{ServerID: id, Token: text(credentials.Data, "serverToken"), Mode: "embedded", Timestamp: time.Now().Unix(), Observation: map[string]any{"cpu_percent": 37, "core": map[string]any{"core_version": "test"}}}, "WebSocket")
	if err != nil {
		t.Fatal(err)
	}
	state, _ := a.DB.GetRecord(ctx, "_observations", id)
	if state.Data["cpu_percent"] != nil || state.Data["core"] == nil {
		t.Fatal(state.Data)
	}
	history, err := a.DB.ListMetrics(ctx, id, time.Now().Add(-time.Minute), 10)
	if err != nil || len(history) != 0 {
		t.Fatal("legacy host history was stored", err)
	}
	server, _ := a.DB.GetRecord(ctx, "servers", id)
	if obs, online, _ := a.selectedObservation(ctx, server); obs != nil || online {
		t.Fatal("unbound server used Agent telemetry")
	}
	response = controllerRequest(t, h, "PUT", "/api/collections/servers/"+id, token, map[string]any{"row": map[string]any{"komariUUID": " node-a "}})
	requireStatus(t, response, 200)
	server, _ = a.DB.GetRecord(ctx, "servers", id)
	if text(server.Data, "komariUUID") != "node-a" {
		t.Fatal(server.Data)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": map[string]any{"name": "duplicate", "address": "127.0.0.1", "komariUUID": "node-a"}}), 400)
	base := "http://komari.test"
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": base})
	cache := store.Record{Collection: "_komariObservations", ID: id, Data: map[string]any{"komari_uuid": "node-a", "komari_base_url": base, "cpu_percent": 12, "online": true, "sampled_at": time.Now().UTC().Format(time.RFC3339Nano)}}
	cache, err = a.DB.SaveRecord(ctx, cache)
	if err != nil {
		t.Fatal(err)
	}
	if obs, online, _ := a.selectedObservation(ctx, server); !online || number(obs, "cpu_percent") != 12 {
		t.Fatal("Komari metrics not selected")
	}
	server.Data["komariUUID"] = "node-b"
	if obs, online, _ := a.selectedObservation(ctx, server); obs != nil || online {
		t.Fatal("binding reused another node's cache")
	}
	server.Data["komariUUID"] = "node-a"
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": "http://other.test"})
	if obs, online, _ := a.selectedObservation(ctx, server); obs != nil || online {
		t.Fatal("changed controller reused old cache")
	}
}
