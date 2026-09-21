package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
)

func TestGeneratedManagementVersioningAndRevocation(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "trojan", Data: map[string]any{"name": "Trojan", "protocol": "trojan", "host": "node.example.test", "port": 443, "password": "fixture-password", "security": "tls", "network": "tcp", "status": "启用"}})
	if err != nil {
		t.Fatal(err)
	}
	var ids, links []string
	for _, name := range []string{"first", "second"} {
		res := controllerRequest(t, h, "POST", "/api/subscription-generator", token, generatorInput{Name: name, NodeIDs: []string{"trojan"}, Format: "clash", Mode: "custom", Categories: []string{"private"}, ExpiresInDays: 7, CreateLink: true})
		requireStatus(t, res, 200)
		data := responseMap(t, res)
		ids = append(ids, text(data["row"].(map[string]any), "id"))
		links = append(links, text(data, "url"))
	}
	list := controllerRequest(t, h, "GET", "/api/generated-subscriptions", token, nil)
	requireStatus(t, list, 200)
	if strings.Contains(list.Body.String(), "?token=") || strings.Contains(list.Body.String(), "fixture-password") {
		t.Fatal("list leaked credentials")
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/generated-subscriptions", "", nil), 401)
	for cycle := 0; cycle < 2; cycle++ {
		order := []map[string]any{}
		for _, id := range ids {
			rec, e := a.DB.GetRecord(ctx, generatedSubscriptionCollection, id)
			if e != nil {
				t.Fatal(e)
			}
			order = append(order, map[string]any{"id": id, "recordVersion": rec.Version})
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/generated-subscriptions/order", token, map[string]any{"rows": order}), 200)
		requireStatus(t, controllerRequest(t, h, "POST", "/api/generated-subscriptions/order", token, map[string]any{"rows": order}), 409)
	}
	rec, err := a.DB.GetRecord(ctx, generatedSubscriptionCollection, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/generated-subscriptions/"+rec.ID, token, map[string]any{"recordVersion": rec.Version, "name": "renamed"}), 200)
	requireStatus(t, controllerRequest(t, h, "PUT", "/api/generated-subscriptions/"+rec.ID, token, map[string]any{"recordVersion": rec.Version, "name": "stale"}), 409)
	requireStatus(t, controllerRequest(t, h, "GET", links[0], "", nil), 200)
	rec, _ = a.DB.GetRecord(ctx, generatedSubscriptionCollection, ids[0])
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/generated-subscriptions/"+rec.ID, token, map[string]any{"recordVersion": rec.Version}), 200)
	requireStatus(t, controllerRequest(t, h, "GET", links[0], "", nil), 404)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/generated-subscriptions/"+rec.ID, token, nil), 404)
}
