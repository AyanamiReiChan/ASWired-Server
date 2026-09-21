package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestExternalSourcesRequireAdminForJWTAndAPITokens(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "source-member", Username: "source-member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	jwt, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	tokenResponse := controllerRequest(t, h, http.MethodPost, "/api/actions", jwt, map[string]any{"action": "token.create", "params": map[string]any{"name": "source access fixture", "scopes": []string{"read", "write"}}})
	requireStatus(t, tokenResponse, http.StatusOK)
	apiToken := text(responseMap(t, tokenResponse), "token")
	var requests atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(realityClientFixtureURI("proxy.example.com", "Imported")))
	}))
	defer fixture.Close()
	row := map[string]any{"name": "private-source-detail", "url": fixture.URL + "/secret-source-token", "intervalSeconds": 300}
	saved := map[string]store.Record{}
	for _, owner := range []string{member.ID, "another-member", ""} {
		record, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "source-" + owner, OwnerID: owner, Data: clone(row)})
		if err != nil {
			t.Fatal(err)
		}
		saved[record.ID] = record
	}
	imported := realityClientFixtureData()
	imported["name"] = "Previously imported node"
	imported["sourceId"] = "source-" + member.ID
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "existing-imported-node", OwnerID: member.ID, Data: imported}); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{jwt, apiToken} {
		requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/sources", token, nil), http.StatusForbidden)
		requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/collections/sources", token, map[string]any{"row": row}), http.StatusForbidden)
		for _, id := range []string{"source-" + member.ID, "source-another-member", "source-", "missing"} {
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
				requireStatus(t, controllerRequest(t, h, method, "/api/collections/sources/"+id, token, map[string]any{"row": row}), http.StatusForbidden)
			}
			requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "source.sync", "targetId": id}), http.StatusForbidden)
		}
		stateResponse := controllerRequest(t, h, http.MethodGet, "/api/state", token, nil)
		requireStatus(t, stateResponse, http.StatusOK)
		data := responseMap(t, stateResponse)["data"].(map[string]any)
		if _, exists := data["sources"]; exists {
			t.Fatal("member workspace exposes external sources")
		}
		if strings.Contains(stateResponse.Body.String(), "private-source-detail") || strings.Contains(stateResponse.Body.String(), "secret-source-token") {
			t.Fatal("source detail leaked through workspace")
		}
		requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/nodes/existing-imported-node", token, nil), http.StatusForbidden)
	}
	cases := []struct {
		name string
		args map[string]any
	}{
		{"sources_list", nil},
		{"sources_get", map[string]any{"id": "source-" + member.ID}},
		{"sources_create", map[string]any{"row": row}},
		{"sources_update", map[string]any{"id": "source-" + member.ID, "row": row}},
		{"sources_delete", map[string]any{"id": "source-" + member.ID, "confirm": true}},
		{"source_sync", map[string]any{"targetId": "source-" + member.ID}},
		{"workspace_list", map[string]any{"collection": "sources"}},
		{"workspace_get", map[string]any{"collection": "sources", "id": "source-" + member.ID}},
		{"workspace_save", map[string]any{"collection": "sources", "row": row}},
		{"workspace_save", map[string]any{"collection": "sources", "id": "source-" + member.ID, "row": row}},
		{"run_action", map[string]any{"action": "source.sync", "targetId": "source-" + member.ID}},
	}
	for _, spec := range cases {
		rpc := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": spec.name, "arguments": spec.args}})
		requireStatus(t, rpc, http.StatusOK)
		result := responseMap(t, rpc)["result"].(map[string]any)
		if !boolean(result, "isError") || !strings.Contains(rpc.Body.String(), "forbidden") || strings.Contains(rpc.Body.String(), "secret-source-token") {
			t.Fatalf("MCP source permission bypass in %s: %s", spec.name, rpc.Body)
		}
	}
	catalog := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	requireStatus(t, catalog, http.StatusOK)
	if strings.Contains(catalog.Body.String(), `"name":"sources_`) || strings.Contains(catalog.Body.String(), `"name":"source_sync"`) {
		t.Fatal("member MCP catalog advertises source management")
	}
	if strings.Contains(catalog.Body.String(), `"name":"nodes_create"`) || !strings.Contains(catalog.Body.String(), `"name":"node_health_check"`) {
		t.Fatal("member node tools disappeared")
	}
	if requests.Load() != 0 {
		t.Fatal("denied request fetched an external source")
	}
	for id, previous := range saved {
		current, err := a.DB.GetRecord(ctx, "sources", id)
		if err != nil || current.Version != previous.Version || current.OwnerID != previous.OwnerID || number(current.Data, "intervalSeconds") != 300 {
			t.Fatalf("denied request changed existing source %s: %v", id, err)
		}
	}
}

func TestAdministratorRetainsExternalSourceManagement(t *testing.T) {
	a, h, adminToken := controllerFixture(t)
	ctx := context.Background()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(realityClientFixtureURI("proxy.example.com", "Imported")))
	}))
	defer fixture.Close()
	created := controllerRequest(t, h, http.MethodPost, "/api/collections/sources", adminToken, map[string]any{"row": map[string]any{"name": "Admin source", "url": fixture.URL}})
	requireStatus(t, created, http.StatusOK)
	id := text(responseMap(t, created)["row"].(map[string]any), "id")
	for _, path := range []string{"/api/collections/sources", "/api/collections/sources/" + id} {
		requireStatus(t, controllerRequest(t, h, http.MethodGet, path, adminToken, nil), http.StatusOK)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPut, "/api/collections/sources/"+id, adminToken, map[string]any{"row": map[string]any{"name": "Updated source"}}), http.StatusOK)
	synced := controllerRequest(t, h, http.MethodPost, "/api/actions", adminToken, map[string]any{"action": "source.sync", "targetId": id})
	requireStatus(t, synced, http.StatusOK)
	if number(responseMap(t, synced), "nodes") != 1 {
		t.Fatalf("admin source sync failed: %s", synced.Body)
	}
	state := responseMap(t, controllerRequest(t, h, http.MethodGet, "/api/state", adminToken, nil))["data"].(map[string]any)
	if len(state["sources"].([]any)) != 1 {
		t.Fatal("administrator lost source workspace data")
	}
	legacy, err := a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "legacy-member-source", OwnerID: "old-member", Data: map[string]any{"name": "Legacy source", "url": fixture.URL, "intervalSeconds": 300}})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPut, "/api/collections/sources/"+legacy.ID, adminToken, map[string]any{"row": map[string]any{"name": "Admin maintained legacy source"}}), http.StatusOK)
	current, err := a.DB.GetRecord(ctx, "sources", legacy.ID)
	if err != nil || current.OwnerID != legacy.OwnerID || number(current.Data, "intervalSeconds") != 300 {
		t.Fatal("admin update changed source owner or sync settings")
	}
	tokenResponse := controllerRequest(t, h, http.MethodPost, "/api/actions", adminToken, map[string]any{"action": "token.create", "params": map[string]any{"name": "admin fixture", "scopes": []string{"read", "write"}}})
	requireStatus(t, tokenResponse, http.StatusOK)
	apiToken := text(responseMap(t, tokenResponse), "token")
	catalog := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	if !strings.Contains(catalog.Body.String(), `"name":"sources_create"`) || !strings.Contains(catalog.Body.String(), `"name":"source_sync"`) {
		t.Fatal("administrator MCP source tools disappeared")
	}
	requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/collections/sources/"+id, adminToken, nil), http.StatusOK)
	if _, err := a.DB.GetRecord(ctx, "sources", id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("admin could not delete source")
	}
	nodes, err := a.DB.ListRecords(ctx, "nodes", "")
	if err != nil || len(nodes) != 1 {
		t.Fatal("source removal unexpectedly deleted imported nodes")
	}
}
