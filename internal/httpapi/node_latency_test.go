package httpapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestNodeHealthSavesLatencyWithoutEnablingDisabledNodes(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, fixture := range []struct {
		id, status, expected string
		managed              bool
	}{
		{"active", "启用", "可达", false},
		{"disabled", "停用", "停用", false},
		{"inactive", "disabled", "disabled", false},
		{"managed", "启用", "启用", true},
	} {
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: fixture.id, Data: map[string]any{"host": "127.0.0.1", "port": port, "status": fixture.status, "managedInbound": fixture.managed, "latencyStatus": "failed", "latencyError": "old failure"}})
		if err != nil {
			t.Fatal(err)
		}
		result := controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "node.health.check", "targetId": fixture.id})
		requireStatus(t, result, http.StatusOK)
		body := responseMap(t, result)
		if text(body, "kind") != "tcp" || body["proxyVerified"] != false || body["latency"] == nil {
			t.Fatalf("incorrect measurement: %v", body)
		}
		record, err := a.DB.GetRecord(ctx, "nodes", fixture.id)
		if err != nil || text(record.Data, "status") != fixture.expected || text(record.Data, "latencyStatus") != "success" || record.Data["latency"] == nil || record.Data["latencyError"] != nil || dateTime(text(record.Data, "testedAt")).IsZero() {
			t.Fatalf("measurement changed enablement or was not saved: %v %v", record.Data, err)
		}
	}
}

func TestNodeHealthFailureReplacesStaleLatency(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	for _, fixture := range []struct {
		id, status, expected string
		port                 any
	}{
		{"refused", "可达", "不可达", port},
		{"disabled", "停用", "停用", port},
		{"invalid", "可达", "不可达", 0},
	} {
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: fixture.id, Data: map[string]any{"host": "127.0.0.1", "port": fixture.port, "status": fixture.status, "latency": 123, "latencyStatus": "success", "testedAt": "2000-01-01T00:00:00Z"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.nodeHealth(ctx, fixture.id); err == nil {
			t.Fatal("failed TCP connection reported success")
		}
		record, err := a.DB.GetRecord(ctx, "nodes", fixture.id)
		if err != nil || record.Data["latency"] != nil || text(record.Data, "latencyStatus") != "failed" || text(record.Data, "latencyError") == "" || text(record.Data, "status") != fixture.expected || dateTime(text(record.Data, "testedAt")).Before(time.Now().Add(-time.Minute)) {
			t.Fatalf("stale successful measurement survived failure: %v %v", record.Data, err)
		}
	}
}

func TestMemberNodeHealthRejectsPrivateDestinationsAndOtherOwners(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	for _, id := range []string{"owner", "other"} {
		if err := a.DB.CreateUser(ctx, store.User{ID: id, Username: id, Role: "user", TokenVersion: 1, PasswordHash: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	token, err := a.Signer.Issue("owner", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []store.Record{
		{Collection: "plans", ID: "node-test-plan", Data: map[string]any{"name": "Node test plan", "status": "启用"}},
		{Collection: "subscriptions", ID: "node-test-sub", OwnerID: "owner", Data: map[string]any{"planId": "node-test-plan", "status": "启用"}},
	} {
		if _, err := a.DB.SaveRecord(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1"} {
		record, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: host, OwnerID: "owner", Data: map[string]any{"uri": realityClientFixtureURI(host, "Private"), "latency": 12, "status": "可达"}})
		if err != nil {
			t.Fatal(err)
		}
		result := controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "node.health.check", "targetId": record.ID})
		requireStatus(t, result, http.StatusBadRequest)
		if text(responseMap(t, result)["error"].(map[string]any), "message") != "节点测速失败，请稍后重试或联系管理员" {
			t.Fatal("member latency response exposed internal details", result.Body.String())
		}
		record, _ = a.DB.GetRecord(ctx, "nodes", record.ID)
		if record.Data["latency"] != nil || text(record.Data, "latencyStatus") != "failed" || !strings.Contains(text(record.Data, "latencyError"), "成员资源不能请求") {
			t.Fatal("private node kept misleading latency or lost administrator diagnostics")
		}
	}
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "other-node", OwnerID: "other", Data: map[string]any{"host": "127.0.0.1", "port": 443, "latency": 8}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "node.health.check", "targetId": "other-node"}), http.StatusForbidden)
	record, _ := a.DB.GetRecord(ctx, "nodes", "other-node")
	if number(record.Data, "latency") != 8 || record.Data["testedAt"] != nil {
		t.Fatal("unauthorized test mutated another member's node")
	}
}

func TestNodeHealthBoundsDNSLookupAndPersistsTimeout(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	defer func() { net.DefaultResolver = original }()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "slow-dns", OwnerID: "member", Data: map[string]any{"host": "slow-node.invalid", "port": 443, "latency": 12}})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = a.nodeHealth(ctx, "slow-dns")
	if err == nil || !strings.Contains(err.Error(), "超时") || time.Since(started) > 6*time.Second {
		t.Fatalf("DNS escaped the single-node deadline: %v, %s", err, time.Since(started))
	}
	record, _ := a.DB.GetRecord(ctx, "nodes", "slow-dns")
	if record.Data["latency"] != nil || text(record.Data, "latencyStatus") != "failed" {
		t.Fatal("DNS timeout was not saved")
	}
}

func TestManagedNodeRefreshPreservesOnlySameAddressMeasurements(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	inbound := realityInboundFixtureData()
	inbound["publicKey"] = realityClientFixtureData()["publicKey"]
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "latency-managed", Data: inbound})
	if err != nil {
		t.Fatal(err)
	}
	for _, measurement := range []map[string]any{
		{"latency": 1.25, "latencyKind": "tcp", "latencyStatus": "success", "testedAt": "2026-09-17T00:00:00Z"},
		{"latencyKind": "tcp", "latencyStatus": "failed", "latencyError": "TCP连接超时", "testedAt": "2026-09-17T00:00:01Z"},
	} {
		if err := a.refreshInboundNodes(ctx); err != nil {
			t.Fatal(err)
		}
		node, _ := a.DB.GetRecord(ctx, "nodes", "inbound-latency-managed")
		for _, field := range []string{"latency", "latencyKind", "latencyStatus", "latencyError", "testedAt"} {
			delete(node.Data, field)
		}
		for key, value := range measurement {
			node.Data[key] = value
		}
		if _, err := a.DB.SaveRecord(ctx, node); err != nil {
			t.Fatal(err)
		}
		if err := a.refreshInboundNodes(ctx); err != nil {
			t.Fatal(err)
		}
		node, _ = a.DB.GetRecord(ctx, "nodes", node.ID)
		for key, expected := range measurement {
			if key == "latency" && number(node.Data, key) != expected || key != "latency" && node.Data[key] != expected {
				t.Fatalf("refresh lost %s: %v", key, node.Data)
			}
		}
	}
	server, _ := a.DB.GetRecord(ctx, "servers", "server")
	server.Data["publicAddress"] = "next.example.test"
	if _, err := a.DB.SaveRecord(ctx, server); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	node, _ := a.DB.GetRecord(ctx, "nodes", "inbound-latency-managed")
	if node.Data["testedAt"] != nil || node.Data["latencyStatus"] != nil || node.Data["latencyError"] != nil {
		t.Fatal("changed destination retained stale result")
	}
}

func TestSourceSyncPreservesMeasurementUntilAddressChanges(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	body := realityClientFixtureURI("node.example.test", "Node")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer fixture.Close()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "latency-source", Data: map[string]any{"name": "Source", "url": fixture.URL, "matchBy": "name"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.syncSource(ctx, "latency-source"); err != nil {
		t.Fatal(err)
	}
	nodes, _ := a.DB.ListRecords(ctx, "nodes", "")
	node := nodes[0]
	node.Data["latency"] = 4.5
	node.Data["latencyStatus"] = "success"
	node.Data["testedAt"] = "2026-09-17T00:00:00Z"
	if _, err := a.DB.SaveRecord(ctx, node); err != nil {
		t.Fatal(err)
	}
	if _, err := a.syncSource(ctx, "latency-source"); err != nil {
		t.Fatal(err)
	}
	current, _ := a.DB.GetRecord(ctx, "nodes", node.ID)
	if number(current.Data, "latency") != 4.5 || text(current.Data, "latencyStatus") != "success" || text(current.Data, "status") != "可达" {
		t.Fatal("subscription refresh discarded same-address measurement")
	}
	delete(current.Data, "latency")
	current.Data["latencyStatus"] = "failed"
	current.Data["latencyError"] = "TCP连接超时"
	if _, err := a.DB.SaveRecord(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := a.syncSource(ctx, "latency-source"); err != nil {
		t.Fatal(err)
	}
	current, _ = a.DB.GetRecord(ctx, "nodes", node.ID)
	if text(current.Data, "status") != "不可达" || text(current.Data, "latencyStatus") != "failed" || current.Data["latency"] != nil {
		t.Fatal("subscription refresh concealed failed measurement")
	}
	body = strings.Replace(body, ":443", ":8443", 1)
	if _, err := a.syncSource(ctx, "latency-source"); err != nil {
		t.Fatal(err)
	}
	current, _ = a.DB.GetRecord(ctx, "nodes", node.ID)
	if current.Data["latency"] != nil || current.Data["testedAt"] != nil || current.Data["latencyStatus"] != nil || text(current.Data, "status") != "待测试" {
		t.Fatal("changed source port retained stale measurement")
	}
	for _, disabled := range []bool{false, true} {
		current.Data["status"] = "停用"
		current.Data["disabled"] = disabled
		if disabled {
			current.Data["status"] = "启用"
		}
		current.Data["latency"] = 2
		current.Data["latencyStatus"] = "success"
		if _, err := a.DB.SaveRecord(ctx, current); err != nil {
			t.Fatal(err)
		}
		if _, err := a.syncSource(ctx, "latency-source"); err != nil {
			t.Fatal(err)
		}
		current, _ = a.DB.GetRecord(ctx, "nodes", node.ID)
		if !disabledStatus(current.Data) || number(current.Data, "latency") != 2 {
			t.Fatal("subscription refresh enabled disabled node")
		}
	}
}

func TestNodeTestAddressRejectsInvalidTargets(t *testing.T) {
	for index, row := range []map[string]any{
		{"host": "example.test", "port": 443.5},
		{"host": "https://example.test", "port": 443},
		{"host": "", "port": 443},
		{"host": "example.test", "port": 65536},
		{"uri": "invalid", "host": "127.0.0.1", "port": 443},
	} {
		if address, err := nodeTestAddress(row); err == nil {
			t.Fatalf("accepted invalid target %d: %s", index, address)
		}
	}
	address, err := nodeTestAddress(map[string]any{"host": "2001:db8::1", "port": 443})
	if err != nil || address != net.JoinHostPort("2001:db8::1", strconv.Itoa(443)) {
		t.Fatal("valid IPv6 address was rejected")
	}
	if _, err := nodeTestAddress(map[string]any{"host": "node.example.test", "port": 443}); err != nil {
		t.Fatal(err)
	}
}
