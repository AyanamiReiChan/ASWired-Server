package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestMemberNodesMatchSubscriptionScopeForJWTAndAPITokens(t *testing.T) {
	a, sub := subscriptionFixture(t)
	t.Cleanup(a.Close)
	ctx := context.Background()
	h := a.Handler()
	u, err := a.DB.UserByID(ctx, sub.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := a.Signer.Issue(u.ID, u.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := a.DB.UserByID(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	adminJWT, err := a.Signer.Issue(admin.ID, admin.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	createdToken := controllerRequest(t, h, http.MethodPost, "/api/actions", jwt, map[string]any{"action": "token.create", "params": map[string]any{"name": "subscription node access", "scopes": []string{"read", "write"}}})
	requireStatus(t, createdToken, http.StatusOK)
	apiToken := text(responseMap(t, createdToken), "token")
	for _, spec := range []struct{ id, owner string }{{"selected-own", u.ID}, {"unselected-own", u.ID}, {"other-owner", "other"}, {"plan-only", ""}, {"disabled", ""}, {"unsupported", ""}} {
		row := realityClientFixtureData()
		row["name"] = spec.id
		row["uri"] = realityClientFixtureURI("127.0.0.1", spec.id)
		row["subscriptionAuthorized"] = true
		row["canManage"] = true
		row["latency"] = 12.34
		row["latencyStatus"] = "success"
		row["latencyKind"] = "tcp"
		row["latencyError"] = "TCP connection to private-internal.example:443 failed"
		row["testedAt"] = time.Now().UTC()
		row["description"] = "Administrator-only node detail"
		if spec.id == "disabled" {
			row["status"] = "停用"
		}
		if spec.id == "unsupported" {
			delete(row, "uri")
			row["network"] = "ws"
		}
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: spec.id, OwnerID: spec.owner, Data: row}); err != nil {
			t.Fatal(err)
		}
	}
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []string{"ss-node", "selected-own", "plan-only", "other-owner", "disabled", "unsupported"}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	sub.Data["nodeIds"] = []string{"ss-node", "selected-own", "other-owner", "disabled", "unsupported"}
	sub.Data["includePrivateNodes"] = true
	if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	selected, err := a.eligibleNodes(ctx, sub)
	if err != nil || len(selected) != 2 {
		t.Fatalf("subscription selection mismatch: %v %v", selected, err)
	}
	for _, token := range []string{jwt, apiToken} {
		listed := controllerRequest(t, h, http.MethodGet, "/api/collections/nodes", token, nil)
		requireStatus(t, listed, http.StatusOK)
		assertMemberNodeRows(t, responseMap(t, listed)["rows"], "ss-node", "selected-own")
		state := controllerRequest(t, h, http.MethodGet, "/api/state", token, nil)
		requireStatus(t, state, http.StatusOK)
		assertMemberNodeRows(t, responseMap(t, state)["data"].(map[string]any)["nodes"], "ss-node", "selected-own")
		for _, id := range []string{"ss-node", "selected-own", "missing"} {
			detail := controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/"+id, token, nil)
			requireStatus(t, detail, http.StatusForbidden)
			if strings.Contains(detail.Body.String(), "Administrator-only") || strings.Contains(detail.Body.String(), "\"row\"") {
				t.Fatal("denied member detail returned node data")
			}
		}
		for _, id := range []string{"unselected-own", "other-owner", "plan-only", "disabled", "unsupported"} {
			requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/"+id, token, nil), http.StatusForbidden)
			requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "node.health.check", "targetId": id}), http.StatusForbidden)
		}
		for _, id := range []string{"ss-node", "selected-own", "unselected-own", "missing"} {
			for _, method := range []string{http.MethodPut, http.MethodDelete} {
				requireStatus(t, controllerRequest(t, h, method, "/api/collections/nodes/"+id, token, map[string]any{"row": realityClientFixtureData()}), http.StatusForbidden)
			}
		}
		requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/collections/nodes", token, map[string]any{"row": realityClientFixtureData()}), http.StatusForbidden)
		result := controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "node.health.check", "targetId": "ss-node"})
		requireStatus(t, result, http.StatusBadRequest)
		if text(responseMap(t, result)["error"].(map[string]any), "message") != "节点测速失败，请稍后重试或联系管理员" {
			t.Fatalf("member latency failure exposed internal details: %s", result.Body)
		}
		shared, err := a.DB.GetRecord(ctx, "nodes", "ss-node")
		if err != nil || text(shared.Data, "status") != "启用" || text(shared.Data, "latencyStatus") != "failed" || !strings.Contains(text(shared.Data, "latencyError"), "成员资源不能请求") {
			t.Fatal("member latency test changed shared node enablement", err)
		}
	}
	config := controllerRequest(t, h, http.MethodGet, "/api/subscriptions/"+sub.ID+"/config?format=clash", jwt, nil)
	requireStatus(t, config, http.StatusOK)
	if !strings.Contains(config.Body.String(), "selected-own") || strings.Contains(config.Body.String(), "unselected-own") || strings.Contains(config.Body.String(), "plan-only") {
		t.Fatal("node library selection diverges from generated subscription")
	}
	temporary := controllerRequest(t, h, http.MethodGet, "/api/temporary-subscriptions", jwt, nil)
	requireStatus(t, temporary, http.StatusOK)
	if strings.Contains(temporary.Body.String(), "unselected-own") || strings.Contains(temporary.Body.String(), "plan-only") {
		t.Fatal("temporary subscription options bypassed node selection")
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/temporary-subscriptions", jwt, map[string]any{"subscriptionId": sub.ID, "nodeId": "unselected-own", "expiresInSeconds": 3600, "maxUses": 2}), http.StatusForbidden)
	catalog := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	requireStatus(t, catalog, http.StatusOK)
	for _, name := range []string{"nodes_get", "nodes_create", "nodes_update", "nodes_delete"} {
		if strings.Contains(catalog.Body.String(), `"name":"`+name+`"`) {
			t.Fatal("member MCP advertises node details or mutations", name)
		}
	}
	for _, spec := range []struct {
		name string
		args map[string]any
	}{
		{"nodes_get", map[string]any{"id": "ss-node"}},
		{"nodes_get", map[string]any{"id": "selected-own"}},
		{"nodes_get", map[string]any{"id": "missing"}},
		{"nodes_get", map[string]any{"id": "unselected-own"}},
		{"workspace_get", map[string]any{"collection": "nodes", "id": "ss-node"}},
		{"workspace_get", map[string]any{"collection": "nodes", "id": "selected-own"}},
		{"workspace_get", map[string]any{"collection": "nodes", "id": "missing"}},
		{"workspace_get", map[string]any{"collection": "nodes", "id": "unselected-own"}},
		{"nodes_create", map[string]any{"row": realityClientFixtureData()}},
		{"nodes_update", map[string]any{"id": "selected-own", "row": realityClientFixtureData()}},
		{"nodes_delete", map[string]any{"id": "selected-own", "confirm": true}},
		{"workspace_save", map[string]any{"collection": "nodes", "row": realityClientFixtureData()}},
		{"node_health_check", map[string]any{"targetId": "unselected-own"}},
		{"run_action", map[string]any{"action": "node.health.check", "targetId": "unselected-own"}},
	} {
		rpc := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": spec.name, "arguments": spec.args}})
		requireStatus(t, rpc, http.StatusOK)
		result := responseMap(t, rpc)["result"].(map[string]any)
		if !boolean(result, "isError") || !strings.Contains(rpc.Body.String(), "forbidden") {
			t.Fatalf("MCP bypass in %s: %s", spec.name, rpc.Body)
		}
	}
	for _, name := range []string{"nodes_list", "workspace_list"} {
		rpc := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": map[string]any{"collection": "nodes"}}})
		requireStatus(t, rpc, http.StatusOK)
		result := responseMap(t, rpc)["result"].(map[string]any)
		if boolean(result, "isError") {
			t.Fatal("member MCP node listing failed", rpc.Body)
		}
		var listed map[string]any
		content := result["content"].([]any)[0].(map[string]any)
		if err := json.Unmarshal([]byte(text(content, "text")), &listed); err != nil {
			t.Fatal(err)
		}
		assertMemberNodeRows(t, listed["rows"], "ss-node", "selected-own")
	}
	adminDetail := controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/selected-own", adminJWT, nil)
	requireStatus(t, adminDetail, http.StatusOK)
	adminNode := responseMap(t, adminDetail)["row"].(map[string]any)
	if text(adminNode, "description") != "Administrator-only node detail" || text(adminNode, "uri") == "" || text(adminNode, "latencyError") == "" || adminNode["recordVersion"] == nil {
		t.Fatal("member restriction removed admin node details")
	}
	adminRows := controllerRequest(t, h, http.MethodGet, "/api/collections/nodes", adminJWT, nil)
	requireStatus(t, adminRows, http.StatusOK)
	if len(responseMap(t, adminRows)["rows"].([]any)) != 7 {
		t.Fatal("member restriction removed admin nodes")
	}
	for _, id := range []string{"selected-own", "unselected-own", "other-owner", "plan-only", "disabled", "unsupported"} {
		record, err := a.DB.GetRecord(ctx, "nodes", id)
		if err != nil || record.Version != 1 {
			t.Fatal("denied request modified stored node", id, err)
		}
	}
}

func assertMemberNodeRows(t *testing.T, value any, ids ...string) {
	t.Helper()
	rows := value.([]any)
	if len(rows) != len(ids) {
		t.Fatalf("expected %v nodes, got %v", ids, rows)
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	for _, raw := range rows {
		row := raw.(map[string]any)
		if !wanted[text(row, "id")] || row["canManage"] != false || row["canTest"] != true || row["subscriptionAuthorized"] != true {
			t.Fatalf("unsafe member node: %v", row)
		}
		delete(wanted, text(row, "id"))
		allowed := map[string]bool{"id": true, "subscriptionAuthorized": true, "canManage": true, "canTest": true, "name": true, "region": true, "protocol": true, "source": true, "tags": true, "status": true, "latency": true, "latencyStatus": true}
		for field := range row {
			if !allowed[field] {
				t.Fatal("member node exposes a detail-only field", field)
			}
		}
		if text(row, "id") == "selected-own" && (number(row, "latency") != 12.34 || text(row, "latencyStatus") != "success") {
			t.Fatal("member node omitted its latency result")
		}
	}
}

func TestMemberNodeAccessRevokedWithInactiveSubscription(t *testing.T) {
	for _, scenario := range []string{"no-subscription", "expired", "subscription-disabled", "plan-disabled", "quota-exhausted"} {
		t.Run(scenario, func(t *testing.T) {
			a, sub := subscriptionFixture(t)
			t.Cleanup(a.Close)
			ctx := context.Background()
			u, _ := a.DB.UserByID(ctx, sub.OwnerID)
			jwt, _ := a.Signer.Issue(u.ID, u.TokenVersion)
			if scenario == "no-subscription" {
				if err := a.DB.DeleteRecord(ctx, "subscriptions", sub.ID); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "plan-disabled" {
				plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
				plan.Data["status"] = "停用"
				if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
					t.Fatal(err)
				}
			} else {
				switch scenario {
				case "expired":
					sub.Data["expires"] = time.Now().Add(-time.Minute).Format(time.RFC3339)
				case "subscription-disabled":
					sub.Data["status"] = "停用"
				case "quota-exhausted":
					sub.Data["limit"] = 1
					_, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "node-quota", "server", sub.ID, sub.OwnerID, "fixture", "downlink", int64(2*gib), 1, 2*gib, time.Now().UnixMilli(), 0, "")
					if err != nil {
						t.Fatal(err)
					}
				}
				if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
					t.Fatal(err)
				}
			}
			h := a.Handler()
			listed := controllerRequest(t, h, http.MethodGet, "/api/collections/nodes", jwt, nil)
			requireStatus(t, listed, http.StatusOK)
			assertMemberNodeRows(t, responseMap(t, listed)["rows"])
			requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/ss-node", jwt, nil), http.StatusForbidden)
			requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/actions", jwt, map[string]any{"action": "node.health.check", "targetId": "ss-node"}), http.StatusForbidden)
		})
	}
}
