package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestOperationsReadRequiresAdminForJWTAndAPITokens(t *testing.T) {
	a, h, adminToken := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "ops-member", Username: "ops-member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	apiTokenResponse := controllerRequest(t, h, http.MethodPost, "/api/actions", memberToken, map[string]any{"action": "token.create", "params": map[string]any{"name": "member read", "scopes": []string{"read"}}})
	requireStatus(t, apiTokenResponse, http.StatusOK)
	apiToken := text(responseMap(t, apiTokenResponse), "token")
	for _, actor := range []string{member.ID, "another-member"} {
		if _, err := a.DB.SaveTask(ctx, store.Task{ID: "task-" + actor, ActorID: actor, ServerID: "private-server", Kind: "core.status", Status: "success", Result: json.RawMessage(`{"privateResult":"operations-only"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	operationCollections := []string{"tasks", "audit", "certificates", "notifications", "extensions", "schedules"}
	for _, collection := range operationCollections[2:] {
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: collection, ID: "private-record", OwnerID: member.ID, Data: map[string]any{"name": "operations-only"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, collection := range []string{"_effectiveLimits", "_limitEvents"} {
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: collection, ID: "private-record", OwnerID: member.ID, Data: map[string]any{"serverId": "private-server"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, token := range []string{memberToken, apiToken} {
		for _, path := range []string{"/api/limits/rules", "/api/limits/triggers", "/api/limits/effective", "/api/limits/events", "/api/traffic?range=1h&interval=1m", "/api/traffic?range=30d", "/api/collections/tasks/task-ops-member", "/api/collections/tasks/task-another-member", "/api/collections/tasks/missing-task"} {
			requireStatus(t, controllerRequest(t, h, http.MethodGet, path, token, nil), http.StatusForbidden)
		}
		for _, collection := range operationCollections {
			for _, suffix := range []string{"", "/private-record"} {
				requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/"+collection+suffix, token, nil), http.StatusForbidden)
			}
		}
		response := controllerRequest(t, h, http.MethodGet, "/api/state", token, nil)
		requireStatus(t, response, http.StatusOK)
		data := responseMap(t, response)["data"].(map[string]any)
		for _, collection := range operationCollections {
			if _, exists := data[collection]; exists {
				t.Fatalf("member workspace contains operations collection %s", collection)
			}
		}
		if strings.Contains(response.Body.String(), "operations-only") || strings.Contains(response.Body.String(), "task-ops-member") {
			t.Fatal("member workspace leaked task data")
		}
	}
	for _, path := range []string{"/api/limits/rules", "/api/limits/triggers", "/api/limits/effective", "/api/limits/events", "/api/traffic?range=1h&interval=1m", "/api/collections/tasks/task-ops-member"} {
		requireStatus(t, controllerRequest(t, h, http.MethodGet, path, adminToken, nil), http.StatusOK)
	}
	adminState := responseMap(t, controllerRequest(t, h, http.MethodGet, "/api/state", adminToken, nil))["data"].(map[string]any)
	if len(adminState["tasks"].([]any)) != 2 {
		t.Fatal("administrator lost task history")
	}
	for _, collection := range operationCollections[2:] {
		if len(adminState[collection].([]any)) != 1 {
			t.Fatalf("administrator lost %s", collection)
		}
	}
	for _, action := range []string{"task.retry", "core.status", "traffic.reconcile", "notification.test", "certificate.deploy"} {
		requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/actions", memberToken, map[string]any{"action": action, "targetId": "task-ops-member"}), http.StatusForbidden)
	}
	for _, spec := range []struct{ name, collection, id string }{{"workspace_get", "tasks", "task-ops-member"}, {"workspace_list", "certificates", ""}, {"certificates_get", "", "private-record"}} {
		rpc := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": spec.name, "arguments": map[string]any{"collection": spec.collection, "id": spec.id}}})
		requireStatus(t, rpc, http.StatusOK)
		result := responseMap(t, rpc)["result"].(map[string]any)
		if !boolean(result, "isError") || !strings.Contains(rpc.Body.String(), "forbidden") || strings.Contains(rpc.Body.String(), "operations-only") {
			t.Fatalf("MCP bypassed operations access: %s", rpc.Body)
		}
	}
	catalog := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	for _, collection := range operationCollections {
		if strings.Contains(catalog.Body.String(), `"name":"`+collection+`_`) {
			t.Fatalf("member catalog advertises %s operations", collection)
		}
	}
}

func TestOperationsRestrictionPreservesPersonalSubscriptionsAndResources(t *testing.T) {
	a, sub := subscriptionFixture(t)
	t.Cleanup(a.Close)
	ctx := context.Background()
	u, err := a.DB.UserByID(ctx, sub.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := a.Signer.Issue(u.ID, u.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	sub.Data["used"] = 1.25
	if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	stateResponse := controllerRequest(t, h, http.MethodGet, "/api/state", jwt, nil)
	requireStatus(t, stateResponse, http.StatusOK)
	state := responseMap(t, stateResponse)["data"].(map[string]any)
	subscriptions := state["subscriptions"].([]any)
	if len(subscriptions) != 1 || number(subscriptions[0].(map[string]any), "used") != 1.25 {
		t.Fatal("personal usage was removed with operations statistics")
	}
	for _, path := range []string{"/api/collections/subscriptions/" + sub.ID, "/api/subscriptions/" + sub.ID + "/config?format=clash", "/api/temporary-subscriptions", "/api/membership"} {
		requireStatus(t, controllerRequest(t, h, http.MethodGet, path, jwt, nil), http.StatusOK)
	}
	temporary := controllerRequest(t, h, http.MethodPost, "/api/temporary-subscriptions", jwt, map[string]any{"subscriptionId": sub.ID, "nodeId": "ss-node", "expiresInSeconds": 3600, "maxUses": 2})
	requireStatus(t, temporary, http.StatusCreated)
	link := text(responseMap(t, temporary), "url")
	requireStatus(t, controllerRequest(t, h, http.MethodGet, link+"&format=clash", "", nil), http.StatusOK)
	requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/ss-node", jwt, nil), http.StatusForbidden)
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/collections/nodes", jwt, map[string]any{"row": realityClientFixtureData()}), http.StatusForbidden)
}
