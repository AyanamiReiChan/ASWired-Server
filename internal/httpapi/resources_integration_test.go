package httpapi

import (
	"context"
	"encoding/base64"
	"github.com/AyanamiReiChan/ASWired-Server/internal/auth"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMemberResourcesEnforceOwnershipAndSafeFetch(t *testing.T) {
	a, h, _ := controllerFixture(t)
	ctx := context.Background()
	password, _ := auth.HashPassword("test-member-password")
	tokens := []string{}
	for _, id := range []string{"member-a", "member-b"} {
		u := store.User{ID: id, Username: id, Role: "user", TokenVersion: 1, PasswordHash: password}
		if e := a.DB.CreateUser(ctx, u); e != nil {
			t.Fatal(e)
		}
		token, _ := a.Signer.Issue(id, 1)
		tokens = append(tokens, token)
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "members", ID: id, OwnerID: id, Data: map[string]any{"name": id, "resourceQuotas": map[string]any{"nodes": 1, "sources": 1}}})
	}
	node := map[string]any{"name": "private node", "uri": realityClientFixtureURI("proxy.example.com", "Test"), "serverId": "forged", "managedInbound": true}
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "legacy-member-node", OwnerID: "member-a", Data: node})
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		requireStatus(t, controllerRequest(t, h, "POST", "/api/collections/nodes", token, map[string]any{"row": node}), 403)
		for _, method := range []string{"GET", "PUT", "DELETE"} {
			requireStatus(t, controllerRequest(t, h, method, "/api/collections/nodes/legacy-member-node", token, map[string]any{"row": node}), 403)
		}
		listed := controllerRequest(t, h, "GET", "/api/collections/nodes", token, nil)
		requireStatus(t, listed, 200)
		if strings.Contains(listed.Body.String(), "private node") {
			t.Fatal("unsubscribed resource leaked")
		}
	}
	if conn, e := publicDial(ctx, "tcp", "127.0.0.1:80"); e == nil {
		conn.Close()
		t.Fatal("member fetched loopback")
	}
	if conn, e := publicDial(ctx, "tcp", "169.254.169.254:80"); e == nil {
		conn.Close()
		t.Fatal("member fetched metadata endpoint")
	}
}
func TestSourceSyncKeepsLocalNameAndDisablesMissing(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	body := realityClientFixtureURI("proxy.example.com", "Original")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer fixture.Close()
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "sources", ID: "source", Data: map[string]any{"name": "fixture", "url": fixture.URL, "prefix": "Prefix "}})
	if _, e := a.syncSource(ctx, "source"); e != nil {
		t.Fatal(e)
	}
	nodes, _ := a.DB.ListRecords(ctx, "nodes", "")
	if len(nodes) != 1 {
		t.Fatal("source import missing")
	}
	node := nodes[0]
	node.Data["name"] = "My alias"
	node.Data["tags"] = []string{"favorite"}
	_, _ = a.DB.SaveRecord(ctx, node)
	if _, e := a.syncSource(ctx, "source"); e != nil {
		t.Fatal(e)
	}
	updated, _ := a.DB.GetRecord(ctx, "nodes", node.ID)
	if text(updated.Data, "name") != "My alias" || len(stringList(updated.Data["tags"])) != 1 {
		t.Fatal("sync removed local metadata")
	}
	body = realityClientFixtureURI("next.example.com", "Next")
	if _, e := a.syncSource(ctx, "source"); e != nil {
		t.Fatal(e)
	}
	removed, _ := a.DB.GetRecord(ctx, "nodes", node.ID)
	if !disabledStatus(removed.Data) {
		t.Fatal("missing source node remained active")
	}
	for _, raw := range []string{"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@proxy.example.com:443#SIP002", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret@proxy.example.com:443")) + "#Legacy"} {
		node, e := parseImportedURI(raw)
		if e != nil || text(node, "method") != "aes-128-gcm" || text(node, "password") != "secret" {
			t.Fatalf("Shadowsocks credentials lost: %v", e)
		}
	}
}
func TestForwardCountersDoNotDoubleCountOrCrossGeneration(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	at := time.Now().UnixMilli()
	snapshot := func(generation string, stamp, up, down int64) map[string]any {
		return map[string]any{"sampled_at": stamp, "items": []any{map[string]any{"rule": map[string]any{"id": "group:0"}, "generation": generation, "received_bytes": up, "sent_bytes": down}}}
	}
	a.accountForwards(ctx, "server", snapshot("one", at, 100, 200))
	a.accountForwards(ctx, "server", snapshot("one", at+1000, 150, 250))
	a.accountForwards(ctx, "server", snapshot("one", at+1000, 150, 250))
	a.accountForwards(ctx, "server", snapshot("two", at+2000, 300, 400))
	rows, e := a.DB.ListRecords(ctx, "_forwardLedger", "")
	if e != nil || len(rows) != 3 {
		t.Fatal("duplicate ledger sample")
	}
	var total int64
	gaps := 0
	for _, row := range rows {
		total += counterInteger(row.Data["received_bytes"]) + counterInteger(row.Data["sent_bytes"])
		if boolean(row.Data, "gap") {
			gaps++
		}
	}
	if total != 100 || gaps != 2 {
		t.Fatalf("forward accounting total=%d gaps=%d", total, gaps)
	}
}
