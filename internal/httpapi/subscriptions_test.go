package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/config"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func realityClientFixtureData() map[string]any {
	return map[string]any{"name": "Test Reality", "protocol": "VLESS", "host": "127.0.0.1", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "network": "tcp", "security": "reality", "sni": "example.test", "publicKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "shortId": "aabb", "flow": "xtls-rprx-vision", "status": "启用"}
}

func realityClientFixtureURI(host, name string) string {
	data := realityClientFixtureData()
	query := url.Values{"type": {"tcp"}, "security": {"reality"}, "sni": {text(data, "sni")}, "pbk": {text(data, "publicKey")}, "sid": {text(data, "shortId")}, "flow": {text(data, "flow")}}
	uri := url.URL{Scheme: "vless", User: url.User(text(data, "uuid")), Host: host + ":443", RawQuery: query.Encode(), Fragment: name}
	return uri.String()
}

func subscriptionFixture(t testing.TB) (*App, store.Record) {
	t.Helper()
	directory := t.TempDir()
	db, err := store.Open(store.Config{Driver: "sqlite", DSN: filepath.Join(directory, "test.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	a, err := New(config.Config{DataDir: directory, JWTSecret: []byte(strings.Repeat("k", 32)), JWTTTL: time.Hour, PublicURL: "http://127.0.0.1:12889"}, db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := db.InitializeAdmin(ctx, store.User{ID: "admin", Username: "admin", Role: "admin", PasswordHash: "test-hash"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(ctx, store.User{ID: "member", Username: "member", Role: "user", PasswordHash: "test-hash"}); err != nil {
		t.Fatal(err)
	}
	save := func(c, id string, data map[string]any) {
		if _, e := db.SaveRecord(ctx, store.Record{Collection: c, ID: id, Data: data}); e != nil {
			t.Fatal(e)
		}
	}
	save("plans", "plan", map[string]any{"name": "Test Plan", "status": "已发布", "limit": float64(10), "cycleDays": 30, "directionFactor": 1})
	save("servers", "server", map[string]any{"name": "Test Server", "address": "127.0.0.1", "multiplier": 3})
	save("nodes", "ss-node", realityClientFixtureData())
	row := map[string]any{"name": "Member Plan", "memberId": "member", "planId": "plan", "status": "启用"}
	request := httptest.NewRequest("POST", "/", nil)
	owner, err := a.prepareSubscription(request, "subscription", row, false)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := db.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "subscription", OwnerID: owner, Data: row})
	if err != nil {
		t.Fatal(err)
	}
	return a, sub
}

func TestClientFormatsAndCompatibility(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"clash", "singbox", "egern", "v2ray", "shadowrocket"} {
		t.Run(format, func(t *testing.T) {
			output, kind, skipped, err := a.renderSubscription(ctx, sub, nodes, format)
			if err != nil || output == "" || skipped != 0 {
				t.Fatalf("render: %s %d %v", output, skipped, err)
			}
			if strings.Contains(kind, "yaml") {
				var result map[string]any
				if err := yaml.Unmarshal([]byte(output), &result); err != nil || result == nil {
					t.Fatalf("invalid YAML: %v", err)
				}
			}
			if format == "clash" {
				assertClashPorts(t, output, 7890, 443)
			}
			if format == "singbox" {
				var result map[string]any
				if json.Unmarshal([]byte(output), &result) != nil || len(result["outbounds"].([]any)) < 2 {
					t.Fatal("invalid sing-box outbounds")
				}
			}
			if format == "v2ray" || format == "shadowrocket" {
				decoded, e := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
				if e != nil || !strings.HasPrefix(string(decoded), "vless://") {
					t.Fatal("invalid URI subscription")
				}
			}
		})
	}
	for _, format := range []string{"stash", "surge", "surfboard", "loon", "qx"} {
		t.Run(format, func(t *testing.T) {
			output, _, skipped, err := a.renderSubscription(ctx, sub, nodes, format)
			if err == nil || output != "" || skipped != len(nodes) {
				t.Fatalf("unsupported Reality format rendered: %s %d %v", output, skipped, err)
			}
		})
	}
	vless := clientNode{Protocol: "vless", Network: "tcp", Security: "reality", Flow: "xtls-rprx-vision"}
	if compatible(vless, "surge") || compatible(vless, "surfboard") {
		t.Fatal("unsupported VLESS was emitted for Surge/Surfboard")
	}
	if !compatible(vless, "clash") || !compatible(vless, "singbox") {
		t.Fatal("Reality was lost from supported formats")
	}
	vless.Name = "Reality"
	vless.Host = "example.com"
	vless.Port = 443
	vless.UUID = "d763b1e1-4631-4af7-b2f8-dbf09bca3c6a"
	vless.PublicKey = text(realityClientFixtureData(), "publicKey")
	vless.ShortID = "aabb"
	c := clashNode(vless)
	if c["uuid"] != vless.UUID || c["reality-opts"] == nil {
		t.Fatal("Clash Reality fields missing")
	}
	eg := egernNode(vless)["vless"].(map[string]any)
	if eg["user_id"] != vless.UUID || eg["transport"].(map[string]any)["tls"] == nil {
		t.Fatal("Egern Reality schema incorrect")
	}
}

func assertClashPorts(t *testing.T, output string, mixedPort, proxyPort int) {
	t.Helper()
	var cfg struct {
		MixedPort int `yaml:"mixed-port"`
		Proxies   []struct {
			Port int `yaml:"port"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(output), &cfg); err != nil {
		t.Fatalf("Clash ports must decode as integers: %v", err)
	}
	if cfg.MixedPort != mixedPort || len(cfg.Proxies) == 0 {
		t.Fatalf("unexpected Clash configuration: %+v", cfg)
	}
	for _, proxy := range cfg.Proxies {
		if proxy.Port != proxyPort {
			t.Fatalf("proxy port = %d, want %d", proxy.Port, proxyPort)
		}
	}
}

func TestMergedSubscriptionPreservesInstanceCredentialsAndOwner(t *testing.T) {
	a, first := subscriptionFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "second-plan", Data: map[string]any{"name": "Second Plan", "status": "已发布", "limit": 10}})
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"name": "Second Instance", "memberId": "member", "planId": "second-plan", "status": "启用"}
	owner, err := a.prepareSubscription(httptest.NewRequest("POST", "/", nil), "second-sub", row, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "second-sub", OwnerID: owner, Data: row})
	if err != nil {
		t.Fatal(err)
	}
	native := realityClientFixtureData()
	native["name"], native["host"], native["inboundId"] = "Shared Native", "node.example.test", "test-inbound"
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "native-node", Data: native})
	if err != nil {
		t.Fatal(err)
	}
	output, _, skipped, err := a.renderMergedSubscription(ctx, []store.Record{first, second}, "clash")
	if err != nil || skipped != 0 {
		t.Fatalf("merge: %v %d", err, skipped)
	}
	var result map[string]any
	if err := yaml.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	uuidByName := map[string]string{}
	for _, v := range result["proxies"].([]any) {
		proxy := v.(map[string]any)
		if proxy["type"] == "vless" {
			uuidByName[text(proxy, "name")] = text(proxy, "uuid")
		}
	}
	if uuidByName["Test Plan · Shared Native"] != text(first.Data, "credentialUUID") || uuidByName["Second Plan · Shared Native"] != text(second.Data, "credentialUUID") || text(first.Data, "credentialUUID") == text(second.Data, "credentialUUID") {
		t.Fatalf("merged credentials lost: %v", uuidByName)
	}
	second.Data["status"] = "停用"
	if _, _, skipped, err := a.renderMergedSubscription(ctx, []store.Record{first, second}, "clash"); err != nil || skipped != 1 {
		t.Fatalf("inactive: %v %d", err, skipped)
	}
	second.OwnerID = "another"
	if _, _, _, err := a.renderMergedSubscription(ctx, []store.Record{first, second}, "clash"); err == nil {
		t.Fatal("mixed owners accepted")
	}
}

func TestTrafficResetBoundaryMarksUnresolvedSampleSplit(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	before := time.Now().Add(-2 * time.Second)
	key := "user>>>" + text(sub.Data, "credentialEmail") + ">>>traffic>>>uplink"
	a.accountStats(ctx, "server", map[string]any{"timestamp": before.UnixMilli(), "generation": "same-core", "reset": false, "counters": map[string]any{key: int64(100)}})
	sub, _ = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	sub.Data["cycleStart"] = before.Add(time.Second).UTC().Format(time.RFC3339Nano)
	sub, err := a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	a.accountStats(ctx, "server", map[string]any{"timestamp": before.Add(2 * time.Second).UnixMilli(), "generation": "same-core", "reset": false, "counters": map[string]any{key: int64(150)}})
	var reason string
	if err := a.DB.DB().QueryRowContext(ctx, `SELECT gap_reason FROM traffic_ledger WHERE gap=1`).Scan(&reason); err != nil || reason != "sample_crosses_cycle_boundary" {
		t.Fatalf("sampling uncertainty missing: %q %v", reason, err)
	}
	total, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil || total != 150 {
		t.Fatalf("boundary billing: %v %v", total, err)
	}
}

func TestSubscriptionOwnerAndTokenRotation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	oldToken := text(sub.Data, "token")
	unauthorized := httptest.NewRequest("GET", "/", nil)
	unauthorized.SetPathValue("id", sub.ID)
	unauthorized = unauthorized.WithContext(context.WithValue(unauthorized.Context(), userKey{}, store.User{ID: "other", Role: "user"}))
	w := httptest.NewRecorder()
	a.subscriptionConfig(w, unauthorized)
	if w.Code != 403 {
		t.Fatalf("cross-user read allowed: %d", w.Code)
	}
	rotation := httptest.NewRequest("POST", "/", nil)
	rotation.SetPathValue("id", sub.ID)
	rotation = rotation.WithContext(context.WithValue(rotation.Context(), userKey{}, store.User{ID: "member", Role: "user"}))
	w = httptest.NewRecorder()
	a.subscriptionRotate(w, rotation)
	if w.Code != 200 {
		t.Fatalf("rotate failed: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	a.publicSubscription(w, httptest.NewRequest("GET", "/api/clash/subscribe?token="+oldToken, nil))
	if w.Code != 401 {
		t.Fatal("old token remained valid")
	}
	renewed, _ := a.DB.GetRecord(context.Background(), "subscriptions", sub.ID)
	if text(renewed.Data, "credentialUUID") != text(sub.Data, "credentialUUID") {
		t.Fatal("link rotation unnecessarily changed core credentials")
	}
	w = httptest.NewRecorder()
	a.publicSubscription(w, httptest.NewRequest("GET", "/api/clash/subscribe?token="+text(renewed.Data, "token"), nil))
	if w.Code != 200 {
		t.Fatalf("new token not usable: %s", w.Body.String())
	}
}

func TestTemplateJavaScriptAndTimeout(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	script, err := a.DB.SaveRecord(ctx, store.Record{Collection: "rules", ID: "script", Data: map[string]any{"script": "function main(config) { config.marker = 'executed'; return config; }"}})
	if err != nil {
		t.Fatal(err)
	}
	sub.Data["scriptId"] = "script"
	out, err := a.applySubscriptionTemplate(ctx, sub, map[string]any{"proxies": []any{}}, "clash")
	if err != nil || out.(map[string]any)["marker"] != "executed" {
		t.Fatalf("script not executed: %v %v", out, err)
	}
	script.Data["script"] = "while(true) {}"
	if _, err := a.DB.SaveRecord(ctx, script); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := a.applySubscriptionTemplate(ctx, sub, map[string]any{}, "clash"); err == nil {
		t.Fatal("infinite script did not time out")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("timeout failed to stop script promptly")
	}
}

func TestTrafficCountersDeduplicateFreezeWeightsAndMarkGaps(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["directionFactor"] = 2
	plan, _ = a.DB.SaveRecord(ctx, plan)
	key := "user>>>" + text(sub.Data, "credentialEmail") + ">>>traffic>>>uplink"
	timestamp := time.Now().UnixMilli()
	report := func(generation, value, at int64) {
		a.accountStats(ctx, "server", map[string]any{"generation": generation, "timestamp": at, "reset": false, "counters": map[string]any{key: value}})
	}
	report(1, 100, timestamp)
	report(1, 100, timestamp)
	report(1, 150, timestamp+1)
	total, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil || total != 900 {
		t.Fatalf("duplicate or lost billing %.0f %v", total, err)
	}
	plan.Data["directionFactor"] = 1
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	report(1, 200, timestamp+2)
	report(2, 20, timestamp+3)
	total, up, down, err := a.subscriptionUsage(ctx, sub)
	if err != nil || total != 1110 || up != 1110 || down != 0 {
		t.Fatalf("frozen factors or restart incorrect %.0f %.0f %.0f %v", total, up, down, err)
	}
	var gaps int
	if err := a.DB.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_ledger WHERE gap=1`).Scan(&gaps); err != nil || gaps != 1 {
		t.Fatalf("restart gap not recorded: %d %v", gaps, err)
	}

	report(1, 190, timestamp+1)
	total, _, _, _ = a.subscriptionUsage(ctx, sub)
	if total != 1110 {
		t.Fatal("out-of-order report charged twice")
	}
	sub, _ = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	sub.Data["limit"] = 1000 / gib
	sub, _ = a.DB.SaveRecord(ctx, sub)
	if err := a.subscriptionActive(ctx, sub); err == nil {
		t.Fatal("real ledger quota did not stop subscription")
	}
}

func TestUserSyncReflectsExpiryAndPreservesIndependentCredentials(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	inboundData := realityInboundFixtureData()
	inboundData["name"], inboundData["tag"], inboundData["publicKey"] = "VLESS", "vless-in", text(realityClientFixtureData(), "publicKey")
	inbound, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "inbound", Data: inboundData})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	users, err := a.usersForInbound(ctx, inbound)
	if err != nil || len(users) != 1 || text(users[0], "id") != text(sub.Data, "credentialUUID") {
		t.Fatalf("user not installed: %v %v", users, err)
	}
	if text(users[0], "email") != text(sub.Data, "credentialEmail")+"."+inbound.ID {
		t.Fatal("per-inbound accounting identity missing")
	}
	sub.Data["expires"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	users, err = a.usersForInbound(ctx, inbound)
	if err != nil || len(users) != 0 {
		t.Fatal("expired instance remained in Agent users")
	}
}

func TestPhysicalNodePoliciesShareEntitlementsAndPreserveRevocation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["speed"] = 100
	plan.Data["connectionLimit"] = 3
	plan.Data["ipLimit"] = 2
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	inboundData := realityInboundFixtureData()
	inboundData["name"], inboundData["tag"], inboundData["publicKey"] = "VLESS", "vless-in", text(realityClientFixtureData(), "publicKey")
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "inbound", Data: inboundData}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "plan-2", Data: map[string]any{"name": "Second", "status": "启用", "speed": 200, "connectionLimit": 5, "ipLimit": 3}}); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"name": "Second subscription", "memberId": "member", "planId": "plan-2", "status": "启用"}
	owner, err := a.prepareSubscription(httptest.NewRequest("POST", "/", nil), "second-sub", row, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "second-sub", OwnerID: owner, Data: row})
	if err != nil {
		t.Fatal(err)
	}
	if text(sub.Data, "credentialUUID") == text(second.Data, "credentialUUID") {
		t.Fatal("instances share credentials")
	}
	actor := store.User{ID: "admin", Role: "admin"}
	a.reconcileUsers(ctx, actor)
	synced, _ := a.DB.GetRecord(ctx, "_policySync", "server")
	policies := synced.Data["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("unexpected policies: %+v", policies)
	}
	active := policies[0].(map[string]any)
	if text(active, "user_id") != "member" || len(stringList(active["emails"])) != 2 || number(active, "bytes_per_second") != 25_000_000 || number(active, "connection_limit") != 5 {
		t.Fatalf("shared policy incorrect: %+v", active)
	}
	oldTask := text(synced.Data, "taskId")
	if err := a.DB.DeleteRecord(ctx, "subscriptions", second.ID); err != nil {
		t.Fatal(err)
	}
	a.reconcileUsers(ctx, actor)
	synced, _ = a.DB.GetRecord(ctx, "_policySync", "server")
	policies = synced.Data["policies"].([]any)
	if len(policies) != 2 {
		t.Fatalf("deleted credentials lost revocation: %+v", policies)
	}
	found := false
	for _, raw := range policies {
		p := raw.(map[string]any)
		if boolean(p, "disabled") && text(p, "user_id") == "member#revoked" {
			found = true
			if len(stringList(p["emails"])) != 1 {
				t.Fatal("wrong revoked identity count")
			}
		}
	}
	if !found {
		t.Fatal("deleted credential can fall back to unlimited")
	}
	old, _ := a.DB.GetTask(ctx, oldTask)
	if old.Status != "superseded" {
		t.Fatal("older queued policy could override newer state")
	}
	if inheritedLimit(map[string]any{"speed": float64(0)}, map[string]any{"speed": float64(100)}, "server", "node", "speed").Value != 0 {
		t.Fatal("explicit unlimited override did not win")
	}
}
