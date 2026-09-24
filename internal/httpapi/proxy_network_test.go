package httpapi

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

// Unrelated task/profile tests explicitly model an upgraded Agent. Capability
// rejection tests below intentionally do not call this helper.
func enableProxyIPv6GuardFixture(a *App, ids ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range ids {
		p := a.peers[id]
		if p == nil {
			p = &peer{LastSeen: time.Now()}
			a.peers[id] = p
		}
		if p.Capabilities == nil {
			p.Capabilities = map[string]bool{}
		}
		p.Capabilities["proxy_ipv6_guard"] = true
	}
}

func TestProxyNetworkDefaultOnlyExplicitFalseDisables(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	for _, settings := range []map[string]any{{}, {"blockProxyIPv6": nil}, {"blockProxyIPv6": true}, {"blockProxyIPv6": "false"}, {"blockProxyIPv6": false}} {
		if err := a.DB.SetSetting(ctx, "settings", settings); err != nil {
			t.Fatal(err)
		}
		got, err := a.proxyIPv6Blocked(ctx)
		want := settings["blockProxyIPv6"] != false
		if err != nil || got != want {
			t.Fatalf("%v: %v %v", settings, got, err)
		}
	}
	if err := a.DB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.proxyIPv6Blocked(ctx); err == nil {
		t.Fatal("storage failure silently changed network policy")
	}
}

func TestProxyNetworkGeneratedPolicyPreservesTransportAndInput(t *testing.T) {
	cfg := map[string]any{
		"inbounds":  []any{map[string]any{"tag": "client"}, map[string]any{"tag": "api"}},
		"api":       map[string]any{"tag": "api"},
		"dns":       map[string]any{"queryStrategy": "UseIPv6", "servers": []any{"2001:db8::53"}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "AsIs"}}, map[string]any{"tag": "relay", "protocol": "vless", "settings": map[string]any{"address": "2001:db8::1"}, "streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "direct"}}}},
		"routing":   map[string]any{"rules": []any{map[string]any{"inboundTag": []any{"api"}, "outboundTag": "api"}, map[string]any{"domain": []any{"full:example.test"}, "outboundTag": "relay"}}},
	}
	before, _ := json.Marshal(cfg)
	protected, err := applyProxyNetworkDefaults(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	rules := protected["routing"].(map[string]any)["rules"].([]any)
	if !reflect.DeepEqual(protected["routing"], cfg["routing"]) {
		t.Fatalf("proxy policy changed user routing: %v", rules)
	}
	if !reflect.DeepEqual(protected["dns"], cfg["dns"]) || !reflect.DeepEqual(protected["outbounds"], cfg["outbounds"]) {
		t.Fatal("proxy business policy changed transport settings")
	}
	rules[1].(map[string]any)["domain"] = []any{"full:changed.test"}
	after, _ := json.Marshal(cfg)
	if string(before) != string(after) {
		t.Fatal("generated policy mutated custom source config")
	}
	unprotected, err := applyProxyNetworkDefaults(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	delete(unprotected, "aswired")
	if !reflect.DeepEqual(unprotected, cfg) {
		t.Fatal("explicit disable did not retain original settings")
	}
}

func TestProxyNetworkCompilerDoesNotMutateStoredGlobalRouting(t *testing.T) {
	a, _, _ := controllerFixture(t)
	server := store.Record{ID: "draft", Data: map[string]any{"globalConfig": map[string]any{"routing": map[string]any{"rules": []any{map[string]any{"network": "tcp,udp", "outboundTag": "direct"}, map[string]any{"inboundTag": []any{"api"}, "outboundTag": "api"}}}}}}
	before, _ := json.Marshal(server.Data)
	compiled, err := a.compileServer(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	if !boolean(compiled["aswired"].(map[string]any), "blockProxyIPv6") {
		t.Fatal("compiler omitted default guard metadata")
	}
	after, _ := json.Marshal(server.Data)
	if string(before) != string(after) {
		t.Fatal("compilation changed server globalConfig")
	}
}

func TestProxyNetworkCompilerPreservesDualStackRoutingModes(t *testing.T) {
	for _, strategy := range []string{"IPOnDemand", "IPIfNonMatch"} {
		t.Run(strategy, func(t *testing.T) {
			a, _, _ := controllerFixture(t)
			ctx := context.Background()
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "dual-stack-entry", Data: realityInboundFixtureData()}); err != nil {
				t.Fatal(err)
			}
			routing := map[string]any{"domainStrategy": strategy, "rules": []any{map[string]any{"type": "field", "ip": []any{"127.0.0.1/32"}, "outboundTag": "direct"}}}
			server := store.Record{ID: "server", Data: map[string]any{"globalConfig": map[string]any{"routing": routing}}}
			compiled, err := a.compileServer(ctx, server)
			if err != nil {
				t.Fatal(err)
			}
			if len(compiled["inbounds"].([]any)) != 1 {
				t.Fatal("fixture must compile a real managed client inbound")
			}
			if !reflect.DeepEqual(compiled["routing"], routing) || len(compiled["outbounds"].([]any)) != 2 {
				t.Fatal("automatic IPv6 blackhole changed dual-stack routing")
			}
			if !boolean(compiled["aswired"].(map[string]any), "blockProxyIPv6") {
				t.Fatal("destination guard policy missing")
			}
		})
	}
}

func TestProxyNetworkQueueRequiresCapabilityAndRejectsStalePolicy(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "guard", Data: map[string]any{"connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	actor := store.User{ID: "admin", Role: "admin"}
	for _, action := range []string{"core.config.apply", "core.config.restore"} {
		if _, err := a.queue(ctx, actor, "guard", action, map[string]any{"blockProxyIPv6": false}); err == nil || !strings.Contains(err.Error(), "升级 Agent") {
			t.Fatalf("missing capability accepted %s: %v", action, err)
		}
	}
	a.mu.Lock()
	a.peers["guard"] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"proxy_ipv6_guard": true}}
	a.mu.Unlock()
	params := map[string]any{"blockProxyIPv6": false, "name": "old.json"}
	task, err := a.queue(ctx, actor, "guard", "core.config.restore", params)
	if err != nil {
		t.Fatal(err)
	}
	var command agentwire.Command
	if err = json.Unmarshal(task.Input, &command); err != nil {
		t.Fatal(err)
	}
	if command.Params["blockProxyIPv6"] != true || params["blockProxyIPv6"] != false {
		t.Fatal("policy was bypassed by command input or mutated caller params")
	}
	if err = a.validateProxyNetworkTask(ctx, task, command); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.peers["guard"].Capabilities["proxy_ipv6_guard"] = false
	a.mu.Unlock()
	if a.permitDispatch(ctx, task) {
		t.Fatal("Agent downgrade between queue and dispatch bypassed capability gate")
	}
	failed, err := a.DB.GetTask(ctx, task.ID)
	if err != nil || failed.Status != "failed" || !strings.Contains(failed.Error, "升级 Agent") {
		t.Fatalf("guard failure was not visible: %v %v", failed, err)
	}
	a.mu.Lock()
	a.peers["guard"].Capabilities["proxy_ipv6_guard"] = true
	a.mu.Unlock()
	if err = a.DB.SetSetting(ctx, "settings", map[string]any{"blockProxyIPv6": false}); err != nil {
		t.Fatal(err)
	}
	if err = a.validateProxyNetworkTask(ctx, task, command); err == nil {
		t.Fatal("stale queued network policy accepted")
	}
	a.mu.Lock()
	delete(a.peers, "guard")
	a.mu.Unlock()
	task, err = a.queue(ctx, actor, "guard", "core.config.restore", nil)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(task.Input, &command)
	if command.Params["blockProxyIPv6"] != false {
		t.Fatal("explicit disable was not passed to Agent")
	}
	delete(command.Params, "blockProxyIPv6")
	if err = a.validateProxyNetworkTask(ctx, task, command); err == nil {
		t.Fatal("legacy queued restore bypassed current policy")
	}
}
