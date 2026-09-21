package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestPlanTemplatesAndValidation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	ids := map[string]any{}
	for _, kind := range []string{"Clash", "Surge", "Loon"} {
		id := strings.ToLower(kind)
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: id, Data: map[string]any{"name": kind, "type": kind, "content": blankTemplate(kind)}})
		if err != nil {
			t.Fatal(err)
		}
		ids[id] = id
	}
	plan.Data["templateIds"] = ids
	if err := a.validatePlanManagement(ctx, plan.Data); err != nil {
		t.Fatal(err)
	}
	plan, _ = a.DB.SaveRecord(ctx, plan)
	for _, format := range []string{"clash", "stash", "surge", "loon"} {
		got, err := a.selectedTemplate(ctx, sub, format)
		want := format
		if format == "stash" {
			want = "clash"
		}
		if err != nil || got.ID != want {
			t.Fatalf("%s template: %s %v", format, got.ID, err)
		}
	}
	if err := a.templateDeleteCheck(ctx, "clash"); err == nil {
		t.Fatal("referenced plan template can be deleted")
	}
	for _, patch := range []map[string]any{{"directionFactor": 3}, {"limit": -1}, {"templateIds": map[string]any{"surge": "clash"}}, {"nodeTraffic": map[string]any{"ss-node": map[string]any{"limit": 1}}}, {"nodeNames": map[string]any{"ss-node": "invalid\nname"}}} {
		row := clone(plan.Data)
		for k, v := range patch {
			row[k] = v
		}
		if a.validatePlanManagement(ctx, row) == nil {
			t.Fatalf("invalid plan accepted: %v", patch)
		}
	}
	plan.Data["nodeNames"] = map[string]any{"ss-node": "套餐专属名称"}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := a.renderSubscription(ctx, sub, nodes, "clash")
	if err != nil || !strings.Contains(out, "套餐专属名称") {
		t.Fatal("alias/template not rendered", err, out)
	}
	original, _ := a.DB.GetRecord(ctx, "nodes", "ss-node")
	if text(original.Data, "name") == "套餐专属名称" {
		t.Fatal("plan alias modified global node")
	}
	admin, _ := a.DB.UserByID(ctx, "admin")
	token, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	requireStatus(t, controllerRequest(t, a.Handler(), "DELETE", "/api/collections/plans/plan", token, nil), 409)
}

func TestPlanNodeAccountingQuotaAndCredentialRevocation(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	in := realityInboundFixtureData()
	in["serverId"] = "server"
	in["publicKey"] = realityClientFixtureData()["publicKey"]
	inbound, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "metered", Data: in})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []string{"inbound-metered"}
	plan.Data["directionFactor"] = 2
	plan.Data["nodeTraffic"] = map[string]any{"inbound-metered": map[string]any{"multiplier": 0.5, "limit": 1000 / gib}}
	if err = a.validatePlanManagement(ctx, plan.Data); err != nil {
		t.Fatal(err)
	}
	plan, err = a.DB.SaveRecord(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	users, err := a.usersForInbound(ctx, inbound)
	if err != nil || len(users) != 1 {
		t.Fatal("initial credential missing", err, len(users))
	}
	key := "user>>>" + text(sub.Data, "credentialEmail") + ".metered>>>traffic>>>downlink"
	at := time.Now().UnixMilli()
	report := func(value int64, offset int64) {
		a.accountStats(ctx, "server", map[string]any{"generation": 1, "timestamp": at + offset, "counters": map[string]any{key: value}})
	}
	report(600, 0)
	total, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil || total != 600 {
		t.Fatal("plan multiplier not applied", total, err)
	}
	plan.Data["nodeTraffic"] = map[string]any{"inbound-metered": map[string]any{"multiplier": 1, "limit": 1000 / gib}}
	if _, err = a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	report(800, 1)
	total, _, _, err = a.subscriptionUsage(ctx, sub)
	if err != nil || total != 1000 {
		t.Fatal("historic multiplier changed", total, err)
	}
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil || len(nodes) != 0 {
		t.Fatal("exhausted node still exported", len(nodes), err)
	}
	users, err = a.usersForInbound(ctx, inbound)
	if err != nil || len(users) != 0 {
		t.Fatal("exhausted credential still generated", len(users), err)
	}
	if err = a.subscriptionActive(ctx, sub); err != nil {
		t.Fatal("node quota incorrectly disabled entire plan", err)
	}
	sub, err = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	sub.Data["cycleStart"] = time.UnixMilli(at + 2).Format(time.RFC3339Nano)
	sub, err = a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	users, err = a.usersForInbound(ctx, inbound)
	if err != nil || len(users) != 1 {
		t.Fatal("new cycle did not restore credential", len(users), err)
	}
}
