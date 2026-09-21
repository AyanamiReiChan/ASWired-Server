package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestRealityPoolRequiresAdminForJWTAndAPITokens(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "legacy-pool-contributor", Username: "legacy-pool-contributor", Role: "user", TokenVersion: 1, PasswordHash: "fixture", CreatedAt: time.Now().Add(-30 * 24 * time.Hour)}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	jwt, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	tokenResponse := controllerRequest(t, h, http.MethodPost, "/api/actions", jwt, map[string]any{"action": "token.create", "params": map[string]any{"name": "pool permission fixture", "scopes": []string{"read", "write"}}})
	requireStatus(t, tokenResponse, http.StatusOK)
	apiToken := text(responseMap(t, tokenResponse), "token")
	for _, record := range []store.Record{
		{Collection: realityPoolCollection, ID: "member-pending", OwnerID: member.ID, Data: map[string]any{"name": "private-pool-target", "domain": "private-pool.example.test", "status": "pending", "enabled": false}},
		{Collection: realityPoolCollection, ID: "approved-target", Data: map[string]any{"name": "private-pool-approved", "domain": "private-pool.example.test", "status": "approved", "enabled": true, "lastProbe": map[string]any{"success": true, "certificateExpires": time.Now().Add(time.Hour).Format(time.RFC3339)}}},
		{Collection: "_realityTargetSettings", ID: "allowlist", Data: map[string]any{"domains": []string{"private-pool.example.test"}}},
		{Collection: "_realityContributionDays", ID: member.ID + "/" + time.Now().UTC().Format("2006-01-02"), OwnerID: member.ID, Data: map[string]any{"count": 3}},
		{Collection: realityScanCollection, ID: "legacy-scan", OwnerID: member.ID, Data: map[string]any{"evidence": "private-scan-evidence"}},
	} {
		if _, err := a.DB.SaveRecord(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	internalCollections := []string{realityPoolCollection, "_realityTargetSettings", "_realityContributionDays", realityScanCollection}
	snapshot := func() string {
		t.Helper()
		rows := map[string][]store.Record{}
		for _, collection := range internalCollections {
			var err error
			rows[collection], err = a.DB.ListRecords(ctx, collection, "")
			if err != nil {
				t.Fatal(err)
			}
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	before := snapshot()
	var dials atomic.Int32
	a.realityScanner = &realityScanTransport{dial: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("denied requests must not probe")
	}}
	body := map[string]any{"domain": "private-pool.example.test", "domains": []string{"private-pool.example.test"}, "name": "changed", "enabled": true, "approve": true, "targets": "private-pool.example.test", "scanId": "legacy-scan", "resultIds": []string{"target"}}
	for _, token := range []string{jwt, apiToken} {
		for _, request := range []struct{ method, path string }{
			{http.MethodGet, "/api/reality-targets"},
			{http.MethodPut, "/api/reality-targets/allowlist"},
			{http.MethodPost, "/api/reality-targets/scan"},
			{http.MethodPost, "/api/reality-targets/scan/import"},
		} {
			requireStatus(t, controllerRequest(t, h, request.method, request.path, token, body), http.StatusForbidden)
		}
		for _, id := range []string{"member-pending", "approved-target", "missing"} {
			for _, method := range []string{http.MethodPut, http.MethodDelete} {
				requireStatus(t, controllerRequest(t, h, method, "/api/reality-targets/"+id, token, body), http.StatusForbidden)
			}
			for _, action := range []string{"probe", "review"} {
				requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/reality-targets/"+id+"/"+action, token, body), http.StatusForbidden)
			}
		}
		for _, collection := range internalCollections {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				requireStatus(t, controllerRequest(t, h, method, "/api/collections/"+collection, token, map[string]any{"row": body}), http.StatusNotFound)
			}
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
				requireStatus(t, controllerRequest(t, h, method, "/api/collections/"+collection+"/member-pending", token, map[string]any{"row": body}), http.StatusNotFound)
			}
		}
		for _, path := range []string{"/api/state"} {
			response := controllerRequest(t, h, http.MethodGet, path, token, nil)
			requireStatus(t, response, http.StatusOK)
			if strings.Contains(response.Body.String(), "_reality") || strings.Contains(response.Body.String(), "private-pool") || strings.Contains(response.Body.String(), "private-scan-evidence") {
				t.Fatalf("pool data leaked through %s", path)
			}
		}
		requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/settings", token, nil), http.StatusForbidden)
	}
	for _, collection := range internalCollections {
		for _, tool := range []string{"workspace_list", "workspace_get", "workspace_save"} {
			response := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{"collection": collection, "id": "member-pending", "row": body}}})
			requireStatus(t, response, http.StatusOK)
			result := responseMap(t, response)["result"].(map[string]any)
			if !boolean(result, "isError") || !strings.Contains(response.Body.String(), "unknown_collection") || strings.Contains(response.Body.String(), "private-pool") {
				t.Fatalf("MCP exposed pool collection via %s: %s", tool, response.Body)
			}
		}
	}
	catalog := controllerRequest(t, h, http.MethodPost, "/mcp", apiToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	requireStatus(t, catalog, http.StatusOK)
	if strings.Contains(catalog.Body.String(), "reality") {
		t.Fatal("member MCP catalog advertises internal pool tools")
	}
	if dials.Load() != 0 || snapshot() != before {
		t.Fatal("denied pool requests performed probes or changed targets, settings, scan evidence or legacy contribution quotas")
	}
}

func TestRealityPoolAdministratorAPITokenRetainsManagement(t *testing.T) {
	a, h, jwt := controllerFixture(t)
	createdToken := controllerRequest(t, h, http.MethodPost, "/api/actions", jwt, map[string]any{"action": "token.create", "params": map[string]any{"name": "admin pool fixture", "scopes": []string{"read", "write"}}})
	requireStatus(t, createdToken, http.StatusOK)
	token := text(responseMap(t, createdToken), "token")
	requireStatus(t, controllerRequest(t, h, http.MethodPut, "/api/reality-targets/allowlist", token, map[string]any{"domains": []string{"example.test"}}), http.StatusOK)
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/reality-targets", token, map[string]any{"domain": "example.test"}), http.StatusNotFound)
	id := "admin-target-fixture"
	if _, err := a.DB.SaveRecord(context.Background(), store.Record{Collection: realityPoolCollection, ID: id, Data: map[string]any{"domain": "example.test", "name": "Admin target", "status": "pending", "enabled": false}}); err != nil {
		t.Fatal(err)
	}
	listed := controllerRequest(t, h, http.MethodGet, "/api/reality-targets", token, nil)
	requireStatus(t, listed, http.StatusOK)
	if !strings.Contains(listed.Body.String(), id) || len(responseMap(t, listed)["allowedDomains"].([]any)) != 1 {
		t.Fatal("administrator lost target or allowlist visibility")
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPut, "/api/reality-targets/"+id, token, map[string]any{"name": "Renamed target", "enabled": false}), http.StatusOK)
	requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/reality-targets/"+id, token, nil), http.StatusOK)
	if _, err := a.DB.GetRecord(context.Background(), realityPoolCollection, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("administrator could not delete target")
	}
}
