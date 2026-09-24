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

func TestRealityNodeProfileRejectsActualUnsupportedConfiguration(t *testing.T) {
	cases := []map[string]any{
		{"protocol": "Trojan"}, {"protocol": "VMess"}, {"protocol": "Shadowsocks"}, {"protocol": "Hysteria2"}, {"protocol": "TUIC"}, {"protocol": "AnyTLS"}, {"protocol": "Snell"},
		{"network": "ws"}, {"network": "grpc"}, {"security": "tls"}, {"security": ""}, {"transport": "WebSocket / Reality"},
		{"uuid": "password"}, {"host": "https://example.test"}, {"port": 65536}, {"port": 443.5}, {"sni": ""}, {"sni": "example.test/path"}, {"publicKey": "fixture-public"}, {"shortId": "abc"}, {"shortId": "gg"}, {"flow": "xtls-rprx-splice"},
		{"settings": map[string]any{"protocol": "trojan"}}, {"streamSettings": map[string]any{"network": "ws"}},
	}
	for _, patch := range cases {
		data := realityClientFixtureData()
		for key, value := range patch {
			data[key] = value
		}
		if _, err := normalizedRealityNode(data, true); err == nil {
			t.Fatalf("accepted unsupported node: %v", patch)
		}
	}
	for _, network := range []string{"", "tcp", "raw"} {
		data := realityClientFixtureData()
		data["network"] = network
		data["shortId"] = ""
		data["flow"] = ""
		if _, err := normalizedRealityNode(data, true); err != nil {
			t.Fatalf("valid TCP/empty SID rejected: %v", err)
		}
	}
	uri := realityClientFixtureURI("proxy.example.test", "Actual")
	for _, raw := range []string{
		strings.Replace(uri, "security=reality", "security=tls", 1),
		strings.Replace(uri, "security=reality", "", 1),
		strings.Replace(uri, "type=tcp", "type=ws", 1),
	} {
		row := realityClientFixtureData()
		row["uri"] = raw
		row["reality-opts"] = map[string]any{"public-key": row["publicKey"]}
		if _, err := normalizedRealityNode(row, true); err == nil {
			t.Fatalf("URI actual profile overwritten by labels: %s", raw)
		}
	}
	base := strings.Split(uri, "#")[0]
	for _, key := range []string{"type", "security", "pbk", "sni", "sid", "flow", "encryption"} {
		raw := base + "&" + key + "=first&" + key + "=second"
		if _, err := parseImportedURI(raw); err == nil {
			t.Fatalf("ambiguous URI query accepted: %s", key)
		}
	}
	for _, raw := range []string{base + "&encryption=unsafe", base + "&peer=other.example.test", base + "&broken=%zz"} {
		if _, err := parseImportedURI(raw); err == nil {
			t.Fatalf("invalid URI query accepted: %s", raw)
		}
	}
	legacy := map[string]any{"name": "Keep name", "protocol": "Trojan", "uri": uri, "settings": map[string]any{"old": true}, "ws-opts": map[string]any{"path": "/old"}, "password": "old-secret", "security": "tls"}
	normalized, err := normalizedRealityNode(legacy, true)
	if err != nil || text(normalized, "name") != "Keep name" || normalized["settings"] != nil || normalized["password"] != nil || normalized["ws-opts"] != nil {
		t.Fatalf("explicit URI replacement did not clear obsolete fields: %v %v", normalized, err)
	}
}

func TestNodeSaveLegacyDisablePreservesCredentialsAndRequiresExplicitValidReplacement(t *testing.T) {
	a, h, adminToken := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "reality-member", Username: "reality-member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []struct{ id, owner, token string }{{"admin-legacy", "", adminToken}, {"member-legacy", member.ID, adminToken}} {
		legacy := map[string]any{"name": "Legacy", "protocol": "Trojan", "host": "example.test", "port": 443, "password": "retained-secret", "network": "ws", "security": "tls", "status": "启用", "settings": map[string]any{"opaque": "preserved"}, "plugin": "v2ray-plugin", "plugin_opts": "tls;host=old.test", "plugin-opts": map[string]any{"mode": "websocket"}, "obfs": "salamander", "obfsPassword": "old-mix", "ports": "443-445"}
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: actor.id, OwnerID: actor.owner, Data: legacy}); err != nil {
			t.Fatal(err)
		}
		detail := controllerRequest(t, h, "GET", "/api/collections/nodes/"+actor.id, actor.token, nil)
		requireStatus(t, detail, http.StatusOK)
		row := responseMap(t, detail)["row"].(map[string]any)
		if !boolean(row, "canManage") {
			t.Fatal("detail omitted management capability")
		}
		row["status"] = "停用"
		requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/nodes/"+actor.id, actor.token, map[string]any{"row": row}), http.StatusOK)
		saved, _ := a.DB.GetRecord(ctx, "nodes", actor.id)
		if text(saved.Data, "password") != "retained-secret" || text(saved.Data, "protocol") != "Trojan" || saved.Data["settings"] == nil || saved.Data["canManage"] != nil {
			t.Fatalf("disabling changed stored legacy config: %v", saved.Data)
		}
		enabled := map[string]any{"name": "Legacy", "status": "启用"}
		result := controllerRequest(t, h, "PUT", "/api/collections/nodes/"+actor.id, actor.token, map[string]any{"row": enabled})
		if result.Code < 400 {
			t.Fatal("legacy node silently enabled")
		}
		replace := map[string]any{"name": "Converted", "status": "启用", "uri": realityClientFixtureURI("proxy.example.test", "New")}
		requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/nodes/"+actor.id, actor.token, map[string]any{"row": replace}), http.StatusOK)
		saved, _ = a.DB.GetRecord(ctx, "nodes", actor.id)
		if text(saved.Data, "protocol") != "VLESS" || text(saved.Data, "security") != "reality" || saved.Data["settings"] != nil || saved.Data["password"] != nil {
			t.Fatalf("explicit conversion failed: %v", saved.Data)
		}
		if _, err := clientNodeFor(saved, store.Record{}); err != nil {
			t.Fatalf("explicit URI replacement retained obsolete protocol extensions: %v", err)
		}
		reject := realityClientFixtureData()
		reject["network"] = "ws"
		rejected := controllerRequest(t, h, "POST", "/api/collections/nodes", actor.token, map[string]any{"row": reject})
		if rejected.Code < 400 {
			t.Fatal("HTTP save accepted websocket node")
		}
	}
}

func TestManagedRealityNodeAllowsSafeInboundOverrides(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	inbound := realityInboundFixtureData()
	inbound["publicKey"] = realityClientFixtureData()["publicKey"]
	inbound["settings"] = map[string]any{"decryption": "none"}
	inbound["streamSettings"] = map[string]any{"network": "tcp", "security": "reality", "sockopt": map[string]any{"tcpFastOpen": true}}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "safe-managed", Data: inbound}); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	node, err := a.DB.GetRecord(ctx, "nodes", "inbound-safe-managed")
	if err != nil || text(node.Data, "network") != "tcp" || text(node.Data, "security") != "reality" {
		t.Fatal("derived Reality node missing actual profile")
	}
	node.Data["settings"] = inbound["settings"]
	node.Data["streamSettings"] = inbound["streamSettings"]
	client, err := a.realitySubscriptionNode(ctx, node, sub)
	if err != nil || client.UUID != text(sub.Data, "credentialUUID") {
		t.Fatalf("safe server-only overrides broke client credential projection: %v", err)
	}
	for _, fields := range []map[string]any{{"sni": "first.example.test, second.example.test", "flow": "无"}, {"sni": "", "serverNames": []string{"first.example.test", "second.example.test"}, "flow": "无"}} {
		projection := store.Record{ID: node.ID, Data: clone(node.Data)}
		for key, value := range fields {
			projection.Data[key] = value
		}
		storedProjection := clone(projection.Data)
		delete(storedProjection, "settings")
		delete(storedProjection, "streamSettings")
		if _, err := normalizedRealityNode(storedProjection, false); err != nil {
			t.Fatalf("editing generated managed node rejected its valid display fields: %v", err)
		}
		client, err := a.realitySubscriptionNode(ctx, projection, sub)
		if err != nil || client.SNI != "first.example.test" || client.Flow != "" {
			t.Fatalf("valid managed multi-SNI or empty flow rejected: %v", err)
		}
	}
	stored, _ := a.DB.GetRecord(ctx, "inbounds", "safe-managed")
	stored.Data["streamSettings"] = map[string]any{"network": "ws"}
	if _, err := a.DB.SaveRecord(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := a.realitySubscriptionNode(ctx, node, sub); err == nil {
		t.Fatal("unsupported authoritative inbound bypassed subscription profile")
	}
}

func TestSpeedtestRejectsUnsupportedTransportInOldQueue(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "endpoints", ID: "home-profile", Data: map[string]any{"name": "Home", "status": "启用"}})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_homeCredentials", ID: "home-profile", Data: map[string]any{"serverToken": strings.Repeat("fixture-token", 3)}})
	actor, _ := a.DB.UserByUsername(ctx, "test-admin")
	bad := map[string]any{"name": "Old", "type": "trojan", "server": "example.test", "port": 443, "password": "secret", "network": "xhttp"}
	if _, err := a.queueHome(ctx, actor, "home-profile", map[string]any{"node": bad}); err == nil {
		t.Fatal("unsupported speedtest accepted")
	}
	old := agentwire.Command{ID: "old-speedtest", Action: "speedtest.run", Params: map[string]any{"node": bad}}
	raw, _ := json.Marshal(old)
	// The queue persists millisecond timestamps. Give the historical task an
	// earlier timestamp so dispatch ordering does not depend on a clock tie.
	_, err := a.DB.SaveTask(ctx, store.Task{ID: old.ID, ServerID: "home-profile", ActorID: actor.ID, Kind: old.Action, Status: "queued", Input: raw, CreatedAt: time.Now().Add(-time.Second), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	task, err := a.queueHome(ctx, actor, "home-profile", map[string]any{"node": realityClientFixtureData()})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := a.acceptHomeReport(ctx, agentwire.Report{ServerID: "home-profile", Token: strings.Repeat("fixture-token", 3), Timestamp: time.Now().Unix()}, "WebSocket")
	if err != nil || len(reply.Commands) != 1 || reply.Commands[0].ID != task.ID {
		t.Fatalf("Reality speedtest dispatch failed: %v %v", reply, err)
	}
	oldTask, _ := a.DB.GetTask(ctx, old.ID)
	if oldTask.Status != "failed" || oldTask.Error == "" {
		t.Fatal("legacy unsupported speedtest remained dispatchable")
	}
}

func TestManagedProxyTaskDispatchAndRetryRejectHistoricalOutbounds(t *testing.T) {
	a, h, token := controllerFixture(t)
	enableProxyIPv6GuardFixture(a, "server")
	ctx := context.Background()
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "connection": "WebSocket"}})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "outbounds", ID: "managed-proxy", Data: map[string]any{"name": "Old proxy", "serverId": "server", "tag": "managed-proxy", "protocol": "trojan"}})
	actor, _ := a.DB.UserByUsername(ctx, "test-admin")
	for _, marked := range []bool{false, true} {
		params := map[string]any{"managedInbounds": marked, "config": map[string]any{"inbounds": []any{}, "outbounds": []any{map[string]any{"tag": "managed-proxy", "protocol": "trojan", "settings": map[string]any{"servers": []any{map[string]any{"address": "example.test", "port": 443, "password": "old"}}}}}}}
		task, err := a.queue(ctx, actor, "server", "core.config.apply", params)
		if err != nil {
			t.Fatal(err)
		}
		if a.permitDispatch(ctx, task) {
			t.Fatal("historical managed proxy dispatched")
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID}), http.StatusBadRequest)
	}
	data := realityClientFixtureData()
	proxy := map[string]any{"tag": "managed-proxy", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "example.test", "port": 443, "users": []any{map[string]any{"id": data["uuid"], "encryption": "none", "flow": "xtls-rprx-vision"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": data["sni"], "publicKey": data["publicKey"], "shortId": "aabb"}}}
	params := map[string]any{"managedInbounds": true, "config": map[string]any{"inbounds": []any{}, "outbounds": []any{proxy, map[string]any{"protocol": "freedom", "tag": "direct"}, map[string]any{"protocol": "blackhole", "tag": "block"}}}}
	task, err := a.queue(ctx, actor, "server", "core.config.apply", params)
	if err != nil || !a.permitDispatch(ctx, task) {
		t.Fatalf("valid managed Reality/direct/block task rejected: %v", err)
	}
	independent := map[string]any{"config": map[string]any{"inbounds": []any{taskInbound("internal-socks", "socks", "tcp", "none")}, "outbounds": []any{map[string]any{"tag": "independent-core-proxy", "protocol": "socks"}}}}
	task, err = a.queue(ctx, actor, "server", "core.config.apply", independent)
	if err != nil || !a.permitDispatch(ctx, task) {
		t.Fatalf("independent raw core capability was changed: %v", err)
	}
}

func TestRealityDistributionExcludesLegacyNodesWithoutChangingRecords(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	legacy, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "legacy-distribution", Data: map[string]any{"name": "Legacy", "protocol": "Trojan", "host": "example.test", "port": 443, "password": "preserved", "status": "启用", "network": "xhttp"}})
	if err != nil {
		t.Fatal(err)
	}
	eligible, err := a.eligibleNodes(ctx, sub)
	if err != nil || len(eligible) != 1 || eligible[0].ID == legacy.ID {
		t.Fatal("unsupported legacy node remained eligible")
	}
	candidates, err := a.subscriptionCandidates(ctx, sub)
	if err != nil || len(candidates) != 2 {
		t.Fatal("subscription lost skip accounting candidates")
	}
	output, _, skipped, err := a.renderSubscription(ctx, sub, candidates, "clash")
	if err != nil || skipped != 1 || strings.Contains(output, "Legacy") {
		t.Fatalf("ordinary subscription returned unsupported node: %v %d", err, skipped)
	}
	output, _, skipped, err = a.renderMergedSubscription(ctx, []store.Record{sub}, "clash")
	if err != nil || skipped != 1 || strings.Contains(output, "Legacy") {
		t.Fatalf("merged subscription returned unsupported node: %v %d", err, skipped)
	}
	stored, _ := a.DB.GetRecord(ctx, "nodes", legacy.ID)
	if stored.Version != legacy.Version || text(stored.Data, "protocol") != "Trojan" || text(stored.Data, "password") != "preserved" {
		t.Fatal("filtering mutated legacy record")
	}
	reality := realityClientFixtureData()
	reality["flow"] = ""
	if _, _, _, err := a.renderSubscription(ctx, sub, []store.Record{{Data: reality}}, "qx"); err == nil {
		t.Fatal("empty flow allowed format that cannot preserve REALITY")
	}
}
