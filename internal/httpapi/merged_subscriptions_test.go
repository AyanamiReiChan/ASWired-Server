package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/yaml.v3"
)

func multiPlanFixture(t *testing.T) (*App, http.Handler, string, string, store.Record, store.Record) {
	t.Helper()
	a, first := subscriptionFixture(t)
	t.Cleanup(a.Close)
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []string{"ss-node"}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ id, host string }{{"ss-node", "first.example.test"}, {"second-node", "second.example.test"}} {
		node, err := a.DB.GetRecord(ctx, "nodes", spec.id)
		if err == store.ErrNotFound {
			node = store.Record{Collection: "nodes", ID: spec.id, Data: realityClientFixtureData()}
		}
		node.Data["host"], node.Data["name"], node.Data["inboundId"] = spec.host, spec.id, "inbound-"+spec.id
		if _, err := a.DB.SaveRecord(ctx, node); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "second-plan", Data: map[string]any{"name": "Second Plan", "status": "已发布", "limit": 300, "nodeIds": []string{"second-node"}}}); err != nil {
		t.Fatal(err)
	}
	var err error
	first, err = a.DB.GetRecord(ctx, "subscriptions", first.ID)
	if err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	adminJWT, err := a.Signer.Issue("admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	memberJWT, err := a.Signer.Issue("member", 0)
	if err != nil {
		t.Fatal(err)
	}
	res := controllerRequest(t, h, "POST", "/api/collections/subscriptions", adminJWT, map[string]any{"row": map[string]any{"id": "second-sub", "name": "Second Instance", "memberId": first.OwnerID, "planId": "second-plan"}})
	requireStatus(t, res, 200)
	second, err := a.DB.GetRecord(ctx, "subscriptions", "second-sub")
	if err != nil {
		t.Fatal(err)
	}
	return a, h, adminJWT, memberJWT, first, second
}

func TestMultiPlanAssignmentPreservesExistingInstanceAndQuota(t *testing.T) {
	a, h, adminJWT, memberJWT, first, second := multiPlanFixture(t)
	ctx := context.Background()
	after, err := a.DB.GetRecord(ctx, "subscriptions", first.ID)
	if err != nil || !reflect.DeepEqual(first.Data, after.Data) || after.Version != first.Version {
		t.Fatal("adding another plan changed the existing instance", err)
	}
	if second.OwnerID != first.OwnerID || number(second.Data, "limit") != 300 || number(first.Data, "limit") != 10 {
		t.Fatal("independent quotas or ownership lost")
	}
	for _, key := range []string{"token", "shortCode", "credentialUUID", "credentialPassword", "credentialEmail"} {
		if text(first.Data, key) == "" || text(first.Data, key) == text(second.Data, key) {
			t.Fatal("credentials not independent", key)
		}
	}
	// A duplicate assignment must not silently reset or replace an existing one.
	row := map[string]any{"id": "duplicate-sub", "name": "Duplicate", "memberId": first.OwnerID, "planId": "second-plan"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/subscriptions", adminJWT, map[string]any{"row": row}), 409)
	row["id"] = first.ID
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/subscriptions", adminJWT, map[string]any{"row": row}), 400)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/subscriptions", memberJWT, map[string]any{"row": row}), 403)
	subs, err := a.DB.ListRecords(ctx, "subscriptions", first.OwnerID)
	if err != nil || len(subs) != 2 {
		t.Fatal("wrong number of independent subscriptions", len(subs), err)
	}
	res := controllerRequest(t, h, "GET", "/api/members/management", adminJWT, nil)
	requireStatus(t, res, 200)
	for _, item := range responseMap(t, res)["rows"].([]any) {
		row := item.(map[string]any)
		if text(row, "id") == first.OwnerID && len(row["subscriptions"].([]any)) != 2 {
			t.Fatal("member management lost a plan")
		}
	}
}

func mergedPath(t *testing.T, body map[string]any) string {
	t.Helper()
	u, err := url.Parse(text(body, "url"))
	if err != nil || u.Query().Get("token") == "" {
		t.Fatal("invalid merged URL", err)
	}
	return u.RequestURI()
}

func mergedProxies(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	requireStatus(t, response, 200)
	var cfg struct {
		Proxies []struct {
			Name   string `yaml:"name"`
			Server string `yaml:"server"`
			UUID   string `yaml:"uuid"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(response.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	proxies := map[string]string{}
	for _, proxy := range cfg.Proxies {
		proxies[proxy.Server] = proxy.UUID
	}
	if len(proxies) != len(cfg.Proxies) {
		t.Fatal("unexpected duplicate or cross-plan node")
	}
	return proxies
}

func TestMergedSelectionOwnInstancesAndCompatibility(t *testing.T) {
	a, h, adminJWT, memberJWT, first, second := multiPlanFixture(t)
	ctx := context.Background()
	if err := a.DB.CreateUser(ctx, store.User{ID: "other", Username: "other", Role: "user", PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	foreign := store.Record{Collection: "subscriptions", ID: "foreign-sub", OwnerID: "other", Data: map[string]any{"name": "Private Other Plan", "planId": "plan"}}
	if _, err := a.DB.SaveRecord(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/account/merged-subscription"
	requireStatus(t, controllerRequest(t, h, "GET", endpoint, "", nil), 401)
	requireStatus(t, controllerRequest(t, h, "PUT", endpoint, "", map[string]any{"enabled": true}), 401)
	res := controllerRequest(t, h, "GET", endpoint, memberJWT, nil)
	requireStatus(t, res, 200)
	view := responseMap(t, res)
	if boolean(view, "enabled") || view["subscriptionIds"] != nil || len(view["subscriptions"].([]any)) != 2 || strings.Contains(res.Body.String(), "foreign-sub") {
		t.Fatal("initial view not limited to own instances", view)
	}
	adminView := controllerRequest(t, h, "GET", endpoint, adminJWT, nil)
	requireStatus(t, adminView, 200)
	if len(responseMap(t, adminView)["subscriptions"].([]any)) != 0 {
		t.Fatal("admin self-service view included other users' subscriptions")
	}
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true})
	requireStatus(t, res, 200)
	path := mergedPath(t, responseMap(t, res))
	proxies := mergedProxies(t, controllerRequest(t, h, "GET", path, "", nil))
	if len(proxies) != 2 || proxies["first.example.test"] != text(first.Data, "credentialUUID") || proxies["second.example.test"] != text(second.Data, "credentialUUID") {
		t.Fatal("legacy all-instance merge changed credentials or node scopes", proxies)
	}
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "subscriptionIds": []string{second.ID}})
	requireStatus(t, res, 200)
	if mergedPath(t, responseMap(t, res)) != path {
		t.Fatal("selecting instances rotated the URL")
	}
	proxies = mergedProxies(t, controllerRequest(t, h, "GET", path, "", nil))
	if len(proxies) != 1 || proxies["second.example.test"] != text(second.Data, "credentialUUID") {
		t.Fatal("selection expanded to unselected plan", proxies)
	}
	for _, invalid := range []any{[]string{foreign.ID}, []string{"missing"}, []string{first.ID, first.ID}, []any{nil}, "all", 12} {
		res := controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "rotate": true, "subscriptionIds": invalid})
		requireStatus(t, res, 400)
		if strings.Contains(res.Body.String(), "Private Other Plan") {
			t.Fatal("selection failure disclosed another member's plan")
		}
	}
	res = controllerRequest(t, h, "GET", endpoint, memberJWT, nil)
	requireStatus(t, res, 200)
	if mergedPath(t, responseMap(t, res)) != path || !reflect.DeepEqual(stringList(responseMap(t, res)["subscriptionIds"]), []string{second.ID}) {
		t.Fatal("rejected selection changed persisted settings")
	}
	for _, forbidden := range []string{"tokenHash", "credentialUUID", "credentialPassword", "foreign-sub"} {
		if strings.Contains(res.Body.String(), forbidden) {
			t.Fatal("merged settings exposed private data", forbidden)
		}
	}
	// Copying a member link and rotating via an older client both retain selection.
	requireStatus(t, controllerRequest(t, h, "POST", "/api/members/member/subscription-link", adminJWT, map[string]any{}), 200)
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "rotate": true})
	requireStatus(t, res, 200)
	newPath := mergedPath(t, responseMap(t, res))
	if newPath == path || !reflect.DeepEqual(stringList(responseMap(t, res)["subscriptionIds"]), []string{second.ID}) {
		t.Fatal("rotation changed selection or retained old token")
	}
	requireStatus(t, controllerRequest(t, h, "GET", path, "", nil), 404)
	proxies = mergedProxies(t, controllerRequest(t, h, "GET", newPath, "", nil))
	if len(proxies) != 1 {
		t.Fatal("rotation expanded selected scope")
	}
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "subscriptionIds": []string{}})
	requireStatus(t, res, 200)
	if responseMap(t, res)["subscriptionIds"] == nil {
		t.Fatal("empty selection became all mode")
	}
	requireStatus(t, controllerRequest(t, h, "GET", newPath, "", nil), 422)
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "subscriptionIds": nil})
	requireStatus(t, res, 200)
	if len(mergedProxies(t, controllerRequest(t, h, "GET", newPath, "", nil))) != 2 {
		t.Fatal("explicit all mode did not restore own valid plans")
	}
	requireStatus(t, controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": false}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", newPath, "", nil), 404)
}

func TestMergedFixedSelectionDoesNotIncludeNewOrReplacementInstances(t *testing.T) {
	a, h, adminJWT, memberJWT, first, second := multiPlanFixture(t)
	ctx := context.Background()
	endpoint := "/api/account/merged-subscription"
	res := controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "subscriptionIds": []string{first.ID}})
	requireStatus(t, res, 200)
	path := mergedPath(t, responseMap(t, res))
	// Even a newly assigned plan does not enter an explicit selection.
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "third-plan", Data: map[string]any{"name": "Third Plan", "status": "启用", "limit": 300, "nodeIds": []string{"second-node"}}}); err != nil {
		t.Fatal(err)
	}
	res = controllerRequest(t, h, "POST", "/api/collections/subscriptions", adminJWT, map[string]any{"row": map[string]any{"id": "third-sub", "name": "Third Instance", "memberId": first.OwnerID, "planId": "third-plan"}})
	requireStatus(t, res, 200)
	proxies := mergedProxies(t, controllerRequest(t, h, "GET", path, "", nil))
	if len(proxies) != 1 || proxies["first.example.test"] != text(first.Data, "credentialUUID") {
		t.Fatal("new assignment expanded fixed selection", proxies)
	}
	if err := a.DB.DeleteRecord(ctx, "subscriptions", first.ID); err != nil {
		t.Fatal(err)
	}
	res = controllerRequest(t, h, "POST", "/api/collections/subscriptions", adminJWT, map[string]any{"row": map[string]any{"id": "replacement-sub", "name": "Replacement", "memberId": first.OwnerID, "planId": "plan"}})
	requireStatus(t, res, 200)
	requireStatus(t, controllerRequest(t, h, "GET", path, "", nil), 422)
	res = controllerRequest(t, h, "GET", endpoint, memberJWT, nil)
	requireStatus(t, res, 200)
	if !reflect.DeepEqual(stringList(responseMap(t, res)["subscriptionIds"]), []string{first.ID}) {
		t.Fatal("missing selected instance silently replaced")
	}
	// The member can explicitly select a remaining instance and recover the same URL.
	res = controllerRequest(t, h, "PUT", endpoint, memberJWT, map[string]any{"enabled": true, "subscriptionIds": []string{second.ID}})
	requireStatus(t, res, 200)
	if mergedPath(t, responseMap(t, res)) != path || len(mergedProxies(t, controllerRequest(t, h, "GET", path, "", nil))) != 1 {
		t.Fatal("selection recovery changed the link")
	}
}

func TestMergedSelectionRechecksLiveEntitlements(t *testing.T) {
	for _, change := range []string{"disabled-instance", "expired-instance", "disabled-plan", "quota-exhausted", "ip-restricted", "deleted-instance", "disabled-account"} {
		t.Run(change, func(t *testing.T) {
			a, h, _, memberJWT, first, second := multiPlanFixture(t)
			ctx := context.Background()
			res := controllerRequest(t, h, "PUT", "/api/account/merged-subscription", memberJWT, map[string]any{"enabled": true, "subscriptionIds": []string{first.ID, second.ID}})
			requireStatus(t, res, 200)
			path := mergedPath(t, responseMap(t, res))
			switch change {
			case "disabled-instance":
				first.Data["status"] = "禁用"
			case "expired-instance":
				first.Data["expires"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
			case "disabled-plan":
				plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
				plan.Data["status"] = "禁用"
				if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
					t.Fatal(err)
				}
			case "quota-exhausted":
				_, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "quota", "server", first.ID, first.OwnerID, "test", "downlink", int64(11*gib), 1, int64(11*gib), time.Now().UnixMilli(), 0, "")
				if err != nil {
					t.Fatal(err)
				}
			case "ip-restricted":
				first.Data["whitelist"] = []string{"192.0.2.8"}
			case "deleted-instance":
				if err := a.DB.DeleteRecord(ctx, "subscriptions", first.ID); err != nil {
					t.Fatal(err)
				}
			case "disabled-account":
				user, _ := a.DB.UserByID(ctx, first.OwnerID)
				user.Disabled = true
				if err := a.DB.UpdateUser(ctx, user); err != nil {
					t.Fatal(err)
				}
			}
			if change == "disabled-instance" || change == "expired-instance" || change == "ip-restricted" {
				if _, err := a.DB.SaveRecord(ctx, first); err != nil {
					t.Fatal(err)
				}
			}
			res = controllerRequest(t, h, "GET", path, "", nil)
			if change == "disabled-account" {
				requireStatus(t, res, 422)
				return
			}
			proxies := mergedProxies(t, res)
			if len(proxies) != 1 || proxies["second.example.test"] != text(second.Data, "credentialUUID") {
				t.Fatal("inactive selected instance still distributed or unaffected plan changed", proxies)
			}
		})
	}
}
