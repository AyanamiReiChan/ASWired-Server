package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func realityInboundFixtureData() map[string]any {
	return map[string]any{"name": "Reality", "serverId": "server", "protocol": "VLESS", "transport": "TCP / Reality", "port": 443, "tag": "reality-in", "target": "example.test:443", "sni": "example.test", "privateKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "publicKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "shortIds": []string{"aabb"}, "flow": "xtls-rprx-vision", "status": "启用"}
}

func TestManagedInboundRejectsOtherProfilesAndAdvancedOverrides(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "address": "127.0.0.1", "connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	admin, _ := a.DB.UserByUsername(ctx, "test-admin")
	token, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	h := a.Handler()
	for _, patch := range []map[string]any{
		{"protocol": "VMess"}, {"protocol": "Trojan"}, {"protocol": "Shadowsocks"}, {"protocol": "Hysteria2"}, {"protocol": "AnyTLS"}, {"protocol": "Snell"},
		{"transport": "TCP"}, {"transport": "WebSocket / TLS"}, {"transport": "gRPC / Reality"}, {"transport": "XHTTP / Reality"},
		{"network": "ws"}, {"security": "tls"},
		{"settings": map[string]any{"clients": []any{map[string]any{"id": "unmanaged"}}}},
		{"settings": map[string]any{"decryption": "unsafe"}},
		{"settings": map[string]any{"fallbacks": []any{map[string]any{"dest": 8080}}}},
		{"settings": "not-an-object"},
		{"streamSettings": map[string]any{"network": "ws"}},
		{"streamSettings": map[string]any{"security": "none"}},
		{"streamSettings": map[string]any{"realitySettings": map[string]any{"privateKey": "override"}}},
		{"streamSettings": map[string]any{"tlsSettings": map[string]any{}}},
		{"streamSettings": map[string]any{"sockopt": "invalid"}},
		{"streamSettings": "not-an-object"},
	} {
		row := realityInboundFixtureData()
		for key, value := range patch {
			row[key] = value
		}
		if _, err := compileInbound(row, nil); err == nil {
			t.Fatalf("compiler accepted override %v", patch)
		}
		result := controllerRequest(t, h, "POST", "/api/collections/inbounds", token, map[string]any{"row": row})
		requireStatus(t, result, http.StatusBadRequest)
	}
	rows, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil || len(rows) != 0 {
		t.Fatalf("rejected inbound persisted: %v %d", err, len(rows))
	}
}

func TestManagedRealityDefaultsCompileAndPreserveManagedCredentials(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "address": "127.0.0.1", "connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	row := realityInboundFixtureData()
	delete(row, "protocol")
	delete(row, "transport")
	row["settings"] = map[string]any{"decryption": "none"}
	row["streamSettings"] = map[string]any{"network": "tcp", "security": "reality", "sockopt": map[string]any{"tcpFastOpen": true}}
	result := controllerRequest(t, h, "POST", "/api/collections/inbounds", token, map[string]any{"row": row})
	requireStatus(t, result, http.StatusOK)
	saved := responseMap(t, result)["row"].(map[string]any)
	stored, err := a.DB.GetRecord(ctx, "inbounds", text(saved, "id"))
	if err != nil || text(stored.Data, "protocol") != "VLESS" || text(stored.Data, "transport") != "TCP / Reality" || text(stored.Data, "publicKey") == "" {
		t.Fatal("new inbound profile or public key missing")
	}
	compiled, err := compileInbound(stored.Data, []map[string]any{{"id": "managed-user", "email": "managed.email", "flow": "xtls-rprx-vision", "inbound": "internal-tag", "protocol": "vless", "speed": 100}})
	if err != nil {
		t.Fatal(err)
	}
	stream := compiled["streamSettings"].(map[string]any)
	settings := compiled["settings"].(map[string]any)
	client := settings["clients"].([]any)[0].(map[string]any)
	if text(compiled, "protocol") != "vless" || text(stream, "network") != "tcp" || text(stream, "security") != "reality" || text(settings, "decryption") != "none" || text(client, "id") != "managed-user" || client["speed"] != nil || client["inbound"] != nil {
		t.Fatalf("compiled management contract changed: %v", compiled)
	}
	reality := stream["realitySettings"].(map[string]any)
	if text(reality, "target") != "example.test:443" || text(reality, "privateKey") != text(stored.Data, "privateKey") || stream["sockopt"] == nil {
		t.Fatal("Reality fields lost")
	}
	for _, key := range []string{"target", "sni"} {
		missing := clone(stored.Data)
		delete(missing, key)
		if _, err := compileInbound(missing, nil); err == nil {
			t.Fatalf("missing Reality %s accepted", key)
		}
	}
}

func TestLegacyManagedInboundRemainsReadableButCannotPublish(t *testing.T) {
	for _, protocol := range []string{"VMess", "AnyTLS", "VLESS"} {
		t.Run(protocol, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			enableProxyIPv6GuardFixture(a, "server")
			ctx := context.Background()
			actor, _ := a.DB.UserByID(ctx, "admin")
			token, _ := a.Signer.Issue(actor.ID, actor.TokenVersion)
			h := a.Handler()
			data := map[string]any{"name": "Legacy", "serverId": "server", "protocol": protocol, "transport": "TCP", "tag": "legacy", "port": 8443, "status": "启用"}
			before, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "legacy", Data: data})
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "inbound-legacy", Data: map[string]any{"name": "Stale published node", "inboundId": "legacy", "managedInbound": true, "status": "启用"}})
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := a.eligibleNodes(ctx, sub)
			if err != nil {
				t.Fatal(err)
			}
			for _, node := range nodes {
				if node.ID == "inbound-legacy" {
					t.Fatal("stale unsupported managed node remained eligible")
				}
			}
			if _, err = a.queueCompile(ctx, actor, "server"); err == nil {
				t.Fatalf("legacy compile was not explicitly blocked: %v", err)
			}
			if _, err = a.usersForInbound(ctx, before); err == nil {
				t.Fatal("legacy user synchronization accepted")
			}
			requireStatus(t, controllerRequest(t, h, "GET", "/api/collections/inbounds/legacy", token, nil), http.StatusOK)
			requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/legacy", token, map[string]any{"row": map[string]any{"name": "Still legacy", "status": "启用"}}), http.StatusBadRequest)
			unchanged, err := a.DB.GetRecord(ctx, "inbounds", "legacy")
			if err != nil || unchanged.Version != before.Version || text(unchanged.Data, "transport") != "TCP" {
				t.Fatal("legacy record changed without explicit conversion")
			}
			requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/legacy", token, map[string]any{"row": map[string]any{"name": "Legacy", "status": "禁用"}}), http.StatusOK)
			cfg, err := a.compile(ctx, "server")
			if err != nil || len(cfg["inbounds"].([]any)) != 0 {
				t.Fatalf("disabled legacy inbound blocked supported config: %v", err)
			}
			saved, _ := a.DB.GetRecord(ctx, "inbounds", "legacy")
			if text(saved.Data, "protocol") != protocol || text(saved.Data, "transport") != "TCP" {
				t.Fatal("disabling implicitly migrated legacy profile")
			}
			converted := realityInboundFixtureData()
			converted["settings"] = map[string]any{}
			converted["streamSettings"] = map[string]any{}
			requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/legacy", token, map[string]any{"row": converted}), http.StatusOK)
			if _, err = a.queueCompile(ctx, actor, "server"); err != nil {
				t.Fatalf("explicit conversion did not permit publication: %v", err)
			}
			requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/inbounds/legacy", token, nil), http.StatusOK)
		})
	}
}

func TestExternalNodesAndProxyOutboundsRequireReality(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("Reality node not eligible: %v", err)
	}
	if _, err := normalizedRealityNode(nodes[0].Data, true); err != nil {
		t.Fatalf("Reality node rejected: %v", err)
	}
	rendered, _, _, err := a.renderSubscription(ctx, sub, nodes, "clash")
	if err != nil || !strings.Contains(rendered, "Test Reality") {
		t.Fatalf("Reality subscription failed: %v", err)
	}
	for _, profile := range []map[string]any{{"protocol": "trojan"}, {"protocol": "Shadowsocks"}, {"network": "ws"}, {"security": "none"}} {
		node := realityClientFixtureData()
		for key, value := range profile {
			node[key] = value
		}
		if _, err := normalizedRealityNode(node, true); err == nil {
			t.Fatalf("unsupported node accepted: %v", profile)
		}
		if output, _, skipped, err := a.renderSubscription(ctx, sub, []store.Record{{ID: "legacy-external", Data: node}}, "clash"); err == nil || output != "" || skipped != 1 {
			t.Fatalf("unsupported historical node rendered: %v, skipped=%d err=%v", profile, skipped, err)
		}
	}
	for _, protocol := range []string{"freedom", "blackhole"} {
		if out, err := compileOutbound(map[string]any{"protocol": protocol, "tag": protocol}); err != nil || text(out, "protocol") != protocol {
			t.Fatalf("infrastructure outbound rejected: %s %v", protocol, err)
		}
	}
	for _, protocol := range []string{"trojan", "vmess", "shadowsocks", "socks", "http", "wireguard"} {
		if _, err := compileOutbound(map[string]any{"protocol": protocol, "tag": "legacy-proxy", "settings": map[string]any{"servers": []any{map[string]any{"address": "example.test", "port": 443, "password": "test"}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls"}}); err == nil {
			t.Fatalf("unsupported proxy outbound accepted: %s", protocol)
		}
	}
	data := realityClientFixtureData()
	reality := map[string]any{"protocol": "vless", "tag": "reality-proxy", "settings": map[string]any{"vnext": []any{map[string]any{"address": "example.test", "port": 443, "users": []any{map[string]any{"id": text(data, "uuid"), "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": text(data, "sni"), "publicKey": text(data, "publicKey"), "shortId": "aabb", "fingerprint": "chrome"}}}
	if out, err := compileOutbound(reality); err != nil || text(out, "protocol") != "vless" {
		t.Fatalf("Reality proxy outbound rejected: %v", err)
	}
	for _, stream := range []map[string]any{{"network": "ws", "security": "reality"}, {"network": "tcp", "security": "tls"}, {"network": "tcp", "security": "none"}} {
		invalid := clone(reality)
		invalid["streamSettings"] = stream
		if _, err := compileOutbound(invalid); err == nil {
			t.Fatalf("unsupported outbound transport accepted: %v", stream)
		}
	}
}

func TestUnsupportedManagedInboundRevokesQueuedUserSynchronization(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	inbound, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "managed", Data: realityInboundFixtureData()})
	if err != nil {
		t.Fatal(err)
	}
	actor, _ := a.DB.UserByID(ctx, "admin")
	a.reconcileUsers(ctx, actor)
	previous, err := a.DB.GetRecord(ctx, "_userSync", "server/managed")
	if err != nil {
		t.Fatal(err)
	}
	inbound.Data["protocol"] = "VMess"
	changed, err := a.DB.SaveRecord(ctx, inbound)
	if err != nil {
		t.Fatal(err)
	}
	a.reconcileUsers(ctx, actor)
	oldTask, err := a.DB.GetTask(ctx, text(previous.Data, "taskId"))
	if err != nil || oldTask.Status != "superseded" {
		t.Fatal("previous managed credentials can still be dispatched")
	}
	current, err := a.DB.GetRecord(ctx, "_userSync", "server/managed")
	if err != nil {
		t.Fatal(err)
	}
	task, err := a.DB.GetTask(ctx, text(current.Data, "taskId"))
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		Params map[string]any `json:"params"`
	}
	if json.Unmarshal(task.Input, &input) != nil || task.Kind != "core.users.sync" || len(input.Params["users"].([]any)) != 0 {
		t.Fatal("unsupported managed users were not revoked")
	}
	final, err := a.DB.GetRecord(ctx, "inbounds", inbound.ID)
	if err != nil || final.Version != changed.Version || text(final.Data, "protocol") != "VMess" {
		t.Fatal("reconciliation changed legacy inbound")
	}
}
