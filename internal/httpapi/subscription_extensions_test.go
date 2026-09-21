package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
)

func TestPrivateNodesRespectOwnershipSourcesAndOptOut(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []string{"ss-node", "own", "other", "own-off"}
	a.DB.SaveRecord(ctx, plan)
	for _, r := range []store.Record{{Collection: "nodes", ID: "own", OwnerID: sub.OwnerID, Data: realityClientFixtureData()}, {Collection: "nodes", ID: "other", OwnerID: "other", Data: realityClientFixtureData()}, {Collection: "sources", ID: "off", OwnerID: sub.OwnerID, Data: map[string]any{"status": "禁用"}}, {Collection: "nodes", ID: "own-off", OwnerID: sub.OwnerID, Data: realityClientFixtureData()}} {
		if r.ID == "own-off" {
			r.Data["sourceId"] = "off"
		}
		if _, e := a.DB.SaveRecord(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	nodes, e := a.eligibleNodes(ctx, sub)
	if e != nil || len(nodes) != 2 {
		t.Fatalf("selected private nodes %v %v", nodes, e)
	}
	for _, node := range nodes {
		if node.ID == "other" || node.ID == "own-off" {
			t.Fatal(node.ID)
		}
	}
	sub.Data["includePrivateNodes"] = false
	nodes, e = a.eligibleNodes(ctx, sub)
	if e != nil || len(nodes) != 1 || nodes[0].ID != "ss-node" {
		t.Fatal(nodes, e)
	}
}
func TestQUICAndSSPluginFieldsSurviveOutput(t *testing.T) {
	sub := store.Record{}
	tuic, e := clientNodeFor(store.Record{ID: "tuic", Data: map[string]any{"uri": "tuic://uuid:secret@example.com:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3", "zero_rtt_handshake": true}}, sub)
	if e != nil {
		t.Fatal(e)
	}
	if tuic.Password != "secret" || tuic.UUID != "uuid" {
		t.Fatal(tuic)
	}
	for _, format := range []string{"clash", "singbox"} {
		if !compatible(tuic, format) {
			t.Fatal(format)
		}
	}
	c := clashNode(tuic)
	s := singboxNode(tuic)
	if c["uuid"] != "uuid" || c["congestion-controller"] != "bbr" || s["udp_relay_mode"] != "quic" || s["zero_rtt_handshake"] != true {
		t.Fatal(c, s)
	}
	hy, e := clientNodeFor(store.Record{ID: "hy", Data: map[string]any{"protocol": "hy2", "host": "example.com", "port": 443, "password": "secret", "obfs": map[string]any{"type": "salamander", "password": "obfs-secret"}}}, sub)
	if e != nil {
		t.Fatal(e)
	}
	if clashNode(hy)["obfs-password"] != "obfs-secret" || singboxNode(hy)["obfs"].(map[string]any)["password"] != "obfs-secret" {
		t.Fatal("obfs lost")
	}
	if compatible(hy, "loon") || !strings.Contains(incompatibilityReason(hy, "loon"), "混淆") {
		t.Fatal("unsupported obfs silently lost")
	}
	ss, e := clientNodeFor(store.Record{ID: "ss", Data: map[string]any{"protocol": "ss", "host": "example.com", "port": 443, "password": "secret", "method": "aes-128-gcm", "plugin": "obfs-local", "plugin_opts": "obfs=tls;obfs-host=example.org"}}, sub)
	if e != nil {
		t.Fatal(e)
	}
	if clashNode(ss)["plugin"] != "obfs" || singboxNode(ss)["plugin"] != "obfs-local" || !strings.Contains(text(singboxNode(ss), "plugin_opts"), "obfs-host=example.org") {
		t.Fatal("plugin lost")
	}
	if compatible(ss, "surge") {
		t.Fatal("plugin lost in unsupported format")
	}
	_, e = clientNodeFor(store.Record{ID: "bad", Data: map[string]any{"protocol": "hy2", "host": "example.com", "port": 443, "password": "p", "realm-opts": map[string]any{"enabled": true}}}, sub)
	if e == nil || !strings.Contains(e.Error(), "realm-opts") {
		t.Fatal("extension not explicitly rejected", e)
	}
}
