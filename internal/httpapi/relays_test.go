package httpapi

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestExternalRelayRewritesConnectionAndRestoresOriginal(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	h := a.Handler()
	admin, _ := a.DB.UserByID(ctx, "admin")
	adminToken, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	member, _ := a.DB.UserByID(ctx, "member")
	token, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	node, _ := a.DB.GetRecord(ctx, "nodes", "ss-node")
	original, err := a.realitySubscriptionNode(ctx, node, sub)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"id": node.ID, "nodeId": node.ID, "name": "Relay", "relayAddress": "[2001:db8::10]:38443", "originalAddress": "forged:1"}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/relays", token, map[string]any{"row": row}), 403)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/relays", adminToken, map[string]any{"row": row}), 200)
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/relays", adminToken, map[string]any{"row": row}), 409)
	relay, _ := a.DB.GetRecord(ctx, "relays", node.ID)
	if text(relay.Data, "originalAddress") == "forged:1" {
		t.Fatal("trusted client original address")
	}
	client, err := a.realitySubscriptionNode(ctx, node, sub)
	if err != nil || client.Host != "2001:db8::10" || client.Port != 38443 {
		t.Fatalf("relay ignored: %+v %v", client, err)
	}
	for _, format := range []string{"clash", "singbox", "egern"} {
		output, _, skipped, err := a.renderSubscription(ctx, sub, []store.Record{node}, format)
		if err != nil || skipped != 0 || !strings.Contains(output, "2001:db8::10") || !strings.Contains(output, "38443") {
			t.Fatalf("subscription format %s ignored relay: %v", format, err)
		}
	}
	client.Host, client.Port = original.Host, original.Port
	if nodeURI(client) != nodeURI(original) {
		t.Fatal("relay changed credentials or REALITY parameters")
	}
	path := "/api/nodes/ss-node/connection?subscriptionId=" + sub.ID
	response := controllerRequest(t, h, "GET", path, token, nil)
	requireStatus(t, response, 200)
	clash := responseMap(t, response)["clash"].(map[string]any)
	if text(clash, "server") != "2001:db8::10" || number(clash, "port") != 38443 {
		t.Fatal("connection did not use relay")
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/collections/relays", token, nil), 403)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/relays/ss-node", token, nil), 403)
	requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/relays/ss-node", adminToken, nil), 200)
	restored, err := a.realitySubscriptionNode(ctx, node, sub)
	if err != nil || nodeURI(restored) != nodeURI(original) {
		t.Fatal("delete did not restore original")
	}
	stored, _ := a.DB.GetRecord(ctx, "nodes", node.ID)
	if text(stored.Data, "host") != text(node.Data, "host") {
		t.Fatal("authoritative node changed")
	}
	tasks, err := a.DB.ListTasks(ctx, "", 100)
	if err != nil || len(tasks) != 0 {
		t.Fatalf("relay created Agent tasks: %v %v", tasks, err)
	}
}

func TestExternalRelayValidationAndSourceChange(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	data := realityClientFixtureData()
	data["uri"] = realityClientFixtureURI("original.example.test", "Original")
	node, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "external", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"bad", "example.test:0", "example.test:65536", "https://example.test:443", "original.example.test:443"} {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/relays", token, map[string]any{"row": map[string]any{"id": node.ID, "nodeId": node.ID, "name": "Relay", "relayAddress": entry}}), 400)
	}
	requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/relays", token, map[string]any{"row": map[string]any{"id": node.ID, "nodeId": node.ID, "name": "Relay", "relayAddress": "relay.example.test:8443"}}), 200)
	client, err := a.realitySubscriptionNode(ctx, node, store.Record{})
	if err != nil || client.Host != "relay.example.test" {
		t.Fatalf("URI override failed: %v %v", client, err)
	}
	node.Data["uri"] = realityClientFixtureURI("changed.example.test", "Original")
	client, err = a.realitySubscriptionNode(ctx, node, store.Record{})
	if err != nil || client.Host != "changed.example.test" {
		t.Fatal("stale mapping applied after source address changed")
	}
}

func TestExternalRelayHealthUsesEntry(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	data := realityClientFixtureData()
	data["host"] = "original.invalid"
	node, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "test", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := nodeTestAddress(data)
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "relays", ID: node.ID, Data: map[string]any{"originalAddress": original, "relayAddress": listener.Addr().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.nodeHealth(ctx, node.ID); err != nil {
		t.Fatalf("health test ignored relay: %v", err)
	}
}
