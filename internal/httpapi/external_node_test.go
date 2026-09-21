package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func externalNodeFixtures() []map[string]any {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	uuid := "11111111-2222-4333-8444-555555555555"
	vmess, _ := json.Marshal(map[string]any{"v": "2", "ps": "VMess WS", "add": "example.test", "port": "443", "id": uuid, "aid": "0", "scy": "chacha20-poly1305", "net": "ws", "host": "cdn.example.test", "path": "/socket?token=a", "tls": "tls", "sni": "tls.example.test", "alpn": "h2,http/1.1"})
	return []map[string]any{
		{"uri": "vmess://" + base64.StdEncoding.EncodeToString(vmess)},
		{"uri": "vless://" + uuid + "@example.test:443?type=ws&security=tls&path=%2Fsocket&host=cdn.example.test#VLESS-WS"},
		{"uri": realityClientFixtureURI("example.test", "REALITY")},
		{"uri": "trojan://p%40ss%3Aword@example.test:443?type=grpc&serviceName=service&sni=tls.example.test#Trojan"},
		{"uri": "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:p@ss:word")) + "@example.test:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcdn.example.test#SS"},
		{"uri": "hysteria://example.test:443?auth=hy-secret&upmbps=20&downmbps=100&obfs=mix#HY1"},
		{"uri": "hy2://hy2-secret@example.test?sni=tls.example.test&insecure=1&obfs=salamander&obfs-password=mix&alpn=h3#HY2"},
		{"uri": "socks5://alice:p%40ss@example.test:1080#SOCKS"},
		{"uri": "https://alice:pass@example.test:443#HTTP"},
		{"uri": "anytls://pass@example.test?sni=tls.example.test#AnyTLS"},
		{"uri": "snell://pass@example.test:443?version=3#Snell"},
		{"uri": "tuic://" + uuid + ":pass@example.test:443?alpn=h3&congestion_control=bbr&udp_relay_mode=quic&zero_rtt_handshake=1#TUIC"},
		{"name": "WireGuard", "type": "wireguard", "server": "example.test", "port": 51820, "private-key": key, "public-key": key, "pre-shared-key": key, "ip": "10.0.0.2", "ipv6": "fd00::2", "mtu": 1280, "reserved": []any{1, 2, 3}},
	}
}

func TestExternalProtocolsPreserveConnectionThroughURIAndClash(t *testing.T) {
	for _, fixture := range externalNodeFixtures() {
		row, err := normalizedProxyNode(fixture, true)
		if err != nil {
			t.Fatalf("fixture %s: %v", text(fixture, "name"), err)
		}
		t.Run(text(row, "protocol"), func(t *testing.T) {
			node, err := clientNodeFor(store.Record{Data: row}, store.Record{})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []map[string]any{{"uri": nodeURI(node)}, clashNode(node)} {
				again, err := normalizedProxyNode(input, true)
				if err != nil {
					t.Fatal(err)
				}
				if nodeImportIdentity(row) != nodeImportIdentity(again) {
					t.Fatalf("connection changed during round trip for %s", node.Protocol)
				}
			}
			for _, format := range []string{"clash", "singbox", "surge", "stash", "egern", "v2ray", "shadowrocket"} {
				if !compatible(node, format) {
					continue
				}
				a, sub := subscriptionFixture(t)
				output, _, skipped, err := a.renderSubscription(context.Background(), sub, []store.Record{{ID: "external", Data: row}}, format)
				if err != nil || skipped != 0 || output == "" {
					t.Fatalf("%s output: %v; skipped %d", format, err, skipped)
				}
			}
		})
	}
}

func TestExternalImportPreviewAtomicityDeduplicationAndSecretRedaction(t *testing.T) {
	a, h, token := controllerFixture(t)
	fixtures := externalNodeFixtures()
	proxies := []any{}
	for _, fixture := range fixtures {
		row, err := normalizedProxyNode(fixture, true)
		if err != nil {
			t.Fatal(err)
		}
		node, err := clientNodeFor(store.Record{Data: row}, store.Record{})
		if err != nil {
			t.Fatal(err)
		}
		proxies = append(proxies, clashNode(node))
	}
	proxies = append(proxies, proxies[0])
	raw, _ := yaml.Marshal(map[string]any{"proxies": proxies})
	body := map[string]any{"content": string(raw), "tags": []string{"imported"}}
	preview := controllerRequest(t, h, "POST", "/api/nodes/import/preview", token, body)
	requireStatus(t, preview, 200)
	if !boolean(responseMap(t, preview), "valid") || number(responseMap(t, preview), "count") != float64(len(fixtures)) {
		t.Fatal(preview.Body.String())
	}
	for _, secret := range []string{"private-key", "pre-shared-key", "hy2-secret", "hy-secret", "p@ss", "mix"} {
		if strings.Contains(preview.Body.String(), secret) {
			t.Fatal("preview exposed credentials")
		}
	}
	rows, _ := a.DB.ListRecords(context.Background(), "nodes", "")
	if len(rows) != 0 {
		t.Fatal("preview persisted data")
	}
	result := controllerRequest(t, h, "POST", "/api/nodes/import", token, body)
	requireStatus(t, result, 201)
	if number(responseMap(t, result), "count") != float64(len(fixtures)) {
		t.Fatal(result.Body.String())
	}
	repeat := controllerRequest(t, h, "POST", "/api/nodes/import", token, body)
	requireStatus(t, repeat, 201)
	if number(responseMap(t, repeat), "count") != 0 {
		t.Fatal("duplicate import")
	}
	rows, _ = a.DB.ListRecords(context.Background(), "nodes", "")
	for _, row := range rows {
		public := rowOf(row, false)
		for _, key := range []string{"password", "privateKey", "private-key", "pre-shared-key", "preSharedKey", "auth-str", "obfs-password", "psk"} {
			if public[key] != nil {
				t.Fatalf("public row leaked %s", key)
			}
		}
	}
	bad := controllerRequest(t, h, "POST", "/api/nodes/import", token, map[string]any{"lines": []string{"trojan://other@example.test:443", "anytls://@example.test:443"}})
	requireStatus(t, bad, 400)
	after, _ := a.DB.ListRecords(context.Background(), "nodes", "")
	if len(after) != len(rows) {
		t.Fatal("invalid batch partially committed")
	}
	first, _ := normalizedProxyNode(map[string]any{"uri": "trojan://first@example.test:443"}, true)
	second, _ := normalizedProxyNode(map[string]any{"uri": "trojan://second@example.test:443"}, true)
	if nodeImportIdentity(first) == nodeImportIdentity(second) {
		t.Fatal("different passwords merged")
	}
}

func TestExternalMixedSourceAndSpeedtest(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	proxies := []any{}
	for _, fixture := range externalNodeFixtures() {
		row, e := normalizedProxyNode(fixture, true)
		if e != nil {
			t.Fatal(e)
		}
		node, _ := clientNodeFor(store.Record{Data: row}, store.Record{})
		proxies = append(proxies, clashNode(node))
	}
	raw, _ := yaml.Marshal(map[string]any{"proxies": proxies})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
	defer server.Close()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "mixed", Data: map[string]any{"name": "Mixed", "url": server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.syncSource(ctx, "mixed")
	if err != nil || number(result, "skipped") != 0 || number(result, "nodes") != float64(len(proxies)) {
		t.Fatalf("mixed source: %v %v", result, err)
	}
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "endpoints", ID: "home", Data: map[string]any{"status": "启用"}})
	actor, _ := a.DB.UserByUsername(ctx, "test-admin")
	for _, proxy := range proxies {
		task, err := a.queueHome(ctx, actor, "home", map[string]any{"node": proxy})
		if err != nil {
			t.Fatal(err)
		}
		var command struct{ Params map[string]any }
		if json.Unmarshal(task.Input, &command) != nil {
			t.Fatal("bad command")
		}
		original, _ := json.Marshal(proxy)
		sent, _ := json.Marshal(command.Params["node"])
		if string(original) != string(sent) {
			t.Fatal("speedtest changed proxy configuration")
		}
	}
}

func TestExternalValidationRejectsIncompleteProfiles(t *testing.T) {
	for _, input := range []map[string]any{
		{"uri": "tuic://not-a-uuid:pass@example.test:443"},
		{"uri": "anytls://@example.test:443"},
		{"uri": "hysteria://example.test:443?auth=pass"},
		{"uri": "trojan://pass@example.test:443?type=ws&type=tcp"},
		{"type": "wireguard", "server": "example.test", "port": 51820, "private-key": "bad"},
		{"uri": "vless://11111111-2222-4333-8444-555555555555@example.test:443?security=reality&type=ws&flow=xtls-rprx-vision"},
	} {
		if _, err := normalizedProxyNode(input, true); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
	fixture := externalNodeFixtures()[0]
	row, err := normalizedProxyNode(fixture, true)
	if err != nil {
		t.Fatal(err)
	}
	copy := clone(row)
	copy["uri"] = "socks5://alice:password@example.test:1080"
	copy["privateKey"] = "old"
	replaced, err := normalizedProxyNode(copy, true)
	if err != nil || replaced["privateKey"] != nil || replaced["uuid"] != nil || text(replaced, "username") != "alice" {
		t.Fatal("URI replacement retained old credentials")
	}
	if reflect.DeepEqual(row, replaced) {
		t.Fatal("replacement did not apply")
	}
}

func TestUDPNodeTCPChecksDoNotWriteFalseFailures(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	for _, protocol := range []string{"Hysteria", "Hysteria2", "TUIC", "WireGuard"} {
		original, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: protocol, Data: map[string]any{"protocol": protocol, "host": "127.0.0.1", "port": 1, "status": "启用"}})
		if err != nil {
			t.Fatal(err)
		}
		original, _ = a.DB.GetRecord(ctx, "nodes", protocol)
		if _, err := a.nodeHealth(ctx, protocol); err == nil {
			t.Fatal("UDP TCP check accepted")
		}
		after, _ := a.DB.GetRecord(ctx, "nodes", protocol)
		if after.Version != original.Version || !reflect.DeepEqual(after.Data, original.Data) {
			t.Fatal("UDP check changed node status")
		}
	}
}
