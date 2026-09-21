package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestRoutingEditorPersistsCompilesAndRejectsStaleChanges(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	server, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "routing-server", Data: map[string]any{"name": "Routing", "connection": "WebSocket"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "legacy-routing", Data: map[string]any{"serverId": server.ID, "routing": map[string]any{"rules": []any{map[string]any{"inboundTag": []any{"api"}, "outboundTag": "api"}, map[string]any{"ip": []any{"127.0.0.1"}, "outboundTag": "direct"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	action := func(name string, params map[string]any) map[string]any {
		r := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": name, "targetId": server.ID, "params": params})
		requireStatus(t, r, 200)
		return responseMap(t, r)
	}
	view := action("routing.get", nil)
	params := map[string]any{"revision": view["revision"], "defaultOutbound": "block", "routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []any{map[string]any{"domain": []any{"full:example.com"}, "outboundTag": "direct", "ruleTag": "preserved-extra"}}}}
	before, _ := a.DB.GetRecord(ctx, "servers", server.ID)
	preview := action("routing.preview", params)
	unchanged, _ := a.DB.GetRecord(ctx, "servers", server.ID)
	if before.Version != unchanged.Version {
		t.Fatal("preview wrote to storage")
	}
	if preview["defaultOutbound"] != "block" {
		t.Fatal("preview did not reorder default")
	}
	saved := action("routing.update", params)
	compiled, err := a.compile(ctx, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	routing := compiled["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	if len(rules) != 2 || text(rules[0].(map[string]any), "outboundTag") != "api" || text(rules[1].(map[string]any), "ruleTag") != "preserved-extra" {
		t.Fatalf("legacy override/API preservation: %v", rules)
	}
	if text(compiled["outbounds"].([]any)[0].(map[string]any), "tag") != "block" {
		t.Fatal("wrong default outbound")
	}
	stale := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "routing.update", "targetId": server.ID, "params": params})
	requireStatus(t, stale, 400)
	if saved["revision"] == view["revision"] {
		t.Fatal("revision did not change")
	}
	params["revision"] = saved["revision"]
	params["defaultOutbound"] = "missing"
	requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "routing.update", "targetId": server.ID, "params": params}), 400)
	after, _ := a.DB.GetRecord(ctx, "servers", server.ID)
	if text(after.Data, "routingDefaultOutbound") != "block" {
		t.Fatal("invalid edit persisted")
	}
}

func TestRoutingBalancersAndValidation(t *testing.T) {
	for _, strategy := range []string{"random", "roundRobin", "leastPing", "leastLoad"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := map[string]any{"outbounds": []any{map[string]any{"tag": "direct"}, map[string]any{"tag": "proxy-one"}}, "routing": map[string]any{"balancers": []any{map[string]any{"tag": "pool", "selector": []any{"proxy-"}, "strategy": map[string]any{"type": strategy}}}, "rules": []any{map[string]any{"inboundTag": []any{"entry"}, "balancerTag": "pool"}}}}
			if err := prepareRouting(cfg, "proxy-one"); err != nil {
				t.Fatal(err)
			}
			if (cfg["observatory"] != nil) != (strategy == "leastPing") || (cfg["burstObservatory"] != nil) != (strategy == "leastLoad") {
				t.Fatalf("incorrect observers: %v", cfg)
			}
		})
	}
	invalid := []string{
		`{"rules":[{"domain":["a"],"outboundTag":"missing"}]}`,
		`{"rules":[{"domain":["a"],"outboundTag":"direct","balancerTag":"pool"}]}`,
		`{"rules":[{"outboundTag":"direct"}]}`,
		`{"rules":[{"domain":"a","outboundTag":"direct"}]}`,
		`{"rules":[null]}`,
		`{"balancers":[{"tag":"pool","selector":["missing"],"strategy":{"type":"random"}}]}`,
		`{"balancers":[{"tag":"pool","selector":["direct"],"strategy":{"type":"invalid"}}]}`,
	}
	for _, raw := range invalid {
		var routing map[string]any
		json.Unmarshal([]byte(raw), &routing)
		cfg := map[string]any{"routing": routing, "outbounds": []any{map[string]any{"tag": "direct"}}}
		if prepareRouting(cfg, "") == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}

func TestRoutingMixedObserversAndFallback(t *testing.T) {
	cfg := map[string]any{"outbounds": []any{map[string]any{"tag": "direct"}}, "routing": map[string]any{"balancers": []any{
		map[string]any{"tag": "ping", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastPing"}},
		map[string]any{"tag": "load", "selector": []any{"direct"}, "strategy": map[string]any{"type": "leastLoad"}},
	}}}
	if err := prepareRouting(cfg, ""); err != nil {
		t.Fatal(err)
	}
	if cfg["observatory"] != nil || cfg["burstObservatory"] == nil {
		t.Fatal("mixed pools must share burst observer")
	}
	for _, strategy := range []string{"random", "roundRobin"} {
		cfg := map[string]any{"outbounds": []any{map[string]any{"tag": "direct"}}, "routing": map[string]any{"balancers": []any{map[string]any{"tag": "fallback", "selector": []any{"direct"}, "strategy": map[string]any{"type": strategy}, "fallbackTag": "direct"}}}}
		if err := prepareRouting(cfg, ""); err != nil {
			t.Fatal(err)
		}
		if cfg["observatory"] == nil {
			t.Fatal("fallback needs observer")
		}
	}
}

func TestReportedCoreVersionIndependentFromProbeSource(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	for _, source := range []string{"native", "komari"} {
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: source, Data: map[string]any{"name": source, "connection": "WebSocket", "probeSource": source, "core": "stale-asset-value"}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: source, Data: map[string]any{"core": map[string]any{"core_version": "26.3.27"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	r := controllerRequest(t, h, "GET", "/api/collections/servers", token, nil)
	requireStatus(t, r, 200)
	if strings.Count(r.Body.String(), `"core":"26.3.27"`) != 2 || strings.Contains(r.Body.String(), "stale-asset-value") {
		t.Fatalf("wrong projection: %s", r.Body)
	}
}

func TestPullEndpointRequiresEncryptedAuthentication(t *testing.T) {
	_, h, token := controllerFixture(t)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/agent/pull", "", map[string]any{}), http.StatusUnauthorized)
	for _, connection := range []string{"pull", "http", "auto"} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/servers", token, map[string]any{"row": map[string]any{"name": "Agent", "address": "127.0.0.1", "connection": connection}}), 200)
	}
}
