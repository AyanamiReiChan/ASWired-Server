package httpapi

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestLimitRulesCatalogDefaultsAndExplicitEmptySources(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	for _, item := range []struct {
		name     string
		settings map[string]any
		mode     string
		enabled  bool
		rules    int
	}{
		{"missing", map[string]any{}, "builtin", true, 2},
		{"null", map[string]any{"behaviorLimits": nil}, "builtin", true, 2},
		{"disabled", map[string]any{"behaviorLimits": map[string]any{"enabled": false}}, "disabled", false, 0},
		{"empty", map[string]any{"behaviorLimits": map[string]any{}}, "empty", true, 0},
		{"invalid", map[string]any{"behaviorLimits": "invalid legacy value"}, "invalid", false, 0},
	} {
		t.Run(item.name, func(t *testing.T) {
			if err := a.DB.SetSetting(ctx, "settings", item.settings); err != nil {
				t.Fatal(err)
			}
			r := controllerRequest(t, h, "GET", "/api/limits/rules", token, nil)
			requireStatus(t, r, 200)
			groups := responseMap(t, r)["groups"].([]any)
			if len(groups) != 1 {
				t.Fatalf("empty installation expanded into sources: %s", r.Body)
			}
			group := groups[0].(map[string]any)
			if text(group, "source") != "global" || text(group, "mode") != item.mode || boolean(group, "enabled") != item.enabled || len(group["rules"].([]any)) != item.rules {
				t.Fatalf("wrong catalog: %s", r.Body)
			}
			if item.mode == "builtin" {
				rule := group["rules"].([]any)[0].(map[string]any)
				if text(rule, "id") != "global/balanced-long" || number(rule, "thresholdMbps") != 80 || number(rule, "durationSeconds") != 600 || number(rule, "limitMbps") != 30 {
					t.Fatalf("defaults drifted: %v", rule)
				}
			}
			var after map[string]any
			if err := a.DB.GetSetting(ctx, "settings", &after); err != nil || !reflect.DeepEqual(after, item.settings) {
				t.Fatalf("catalog persisted projected defaults: %v %v", after, err)
			}
		})
	}
}

func TestLimitRulesCatalogShowsConfiguredSourcesWithoutCredentialsOrExpansion(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	save := func(collection, id, owner string, data map[string]any) {
		t.Helper()
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: collection, ID: id, OwnerID: owner, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	member := store.User{ID: "custom-member", Username: "member-name", PasswordHash: "never-return-password", Role: "user"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	rule := map[string]any{"id": "steady", "type": "sustained", "thresholdMbps": 100, "durationSeconds": 60, "limitMbps": 25, "penaltySeconds": 120}
	save("servers", "server-a", "", map[string]any{"name": "Friendly server", "sshPassword": "never-return-ssh"})
	save("nodes", "node-a", "", map[string]any{"name": "Friendly node", "password": "never-return-node"})
	save("plans", "inherited-plan", "", map[string]any{"name": "Inherited", "behaviorLimits": nil})
	save("plans", "unlimited-plan", "", map[string]any{"name": "Unlimited"})
	save("plans", "explicit-plan", "", map[string]any{"name": "Custom plan", "behaviorLimits": map[string]any{"enabled": false, "rules": []any{rule}}, "speed": 100, "nodeLimits": map[string]any{"node-a": map[string]any{"speed": 0}, "server-a": map[string]any{"speed": 15}}, "quotaMode": "throttle", "quotaSpeedMbps": 5, "password": "never-return-plan"})
	save("members", member.ID, member.ID, map[string]any{"name": "Friendly member", "behaviorLimits": map[string]any{}, "speed": 0, "token": "never-return-member"})
	save("subscriptions", "inherited-sub", member.ID, map[string]any{"planId": "inherited-plan", "limit": 10, "token": "never-return-sub"})
	save("subscriptions", "custom-sub", member.ID, map[string]any{"name": "Custom subscription", "planId": "explicit-plan", "limit": 12, "quotaSpeedMbps": 2, "token": "never-return-sub"})
	save("subscriptions", "unlimited-sub", member.ID, map[string]any{"planId": "unlimited-plan", "limit": 0, "quotaMode": "stop"})
	save("_effectiveLimits", "server-a/"+member.ID, member.ID, map[string]any{"serverId": "server-a", "userId": member.ID, "sampleMbps": 999})
	r := controllerRequest(t, h, "GET", "/api/limits/rules", token, nil)
	requireStatus(t, r, 200)
	if strings.Contains(r.Body.String(), "never-return") || strings.Contains(r.Body.String(), "sampleMbps") {
		t.Fatalf("catalog leaked unrelated data: %s", r.Body)
	}
	result := responseMap(t, r)
	groups := map[string]map[string]any{}
	for _, raw := range result["groups"].([]any) {
		row := raw.(map[string]any)
		groups[text(row, "id")] = row
	}
	if len(groups) != 5 || groups["plan:inherited-plan"] != nil || groups["subscription:inherited-sub"] != nil {
		t.Fatalf("inherited sources expanded: %s", r.Body)
	}
	plan := groups["plan:explicit-plan"]
	if text(plan, "mode") != "disabled" || len(plan["rules"].([]any)) != 5 {
		t.Fatalf("missing explicit rules: %v", plan)
	}
	planRules := map[string]map[string]any{}
	for _, raw := range plan["rules"].([]any) {
		row := raw.(map[string]any)
		planRules[text(row, "id")] = row
	}
	if boolean(planRules["plan:explicit-plan/steady"], "enabled") || !boolean(planRules["plan:explicit-plan/speed"], "enabled") {
		t.Fatal("behavior disabled must not disable independent fixed limits")
	}
	if number(planRules["plan:explicit-plan/speed/node-a"], "limitMbps") != 0 || text(planRules["plan:explicit-plan/speed/node-a"], "resourceName") != "Friendly node" {
		t.Fatal("explicit unlimited resource entitlement lost")
	}
	if text(groups["member:"+member.ID], "mode") != "empty" || text(groups["member:"+member.ID], "name") != "Friendly member" {
		t.Fatal("explicit empty member policy lost")
	}
	subRule := groups["subscription:custom-sub"]["rules"].([]any)[0].(map[string]any)
	if text(subRule, "quotaMode") != "throttle" || number(subRule, "limitMbps") != 2 || number(subRule, "quotaGB") != 12 {
		t.Fatalf("quota override failed to inherit mode: %v", subRule)
	}
	if boolean(groups["subscription:unlimited-sub"]["rules"].([]any)[0].(map[string]any), "enabled") {
		t.Fatal("unlimited subscription cannot trigger quota")
	}
	counts := result["inheritance"].(map[string]any)
	if number(counts, "planInherited") != 2 || number(counts, "planOverrides") != 1 || number(counts, "memberInherited") != 1 || number(counts, "memberOverrides") != 1 {
		t.Fatalf("wrong source counts: %v", counts)
	}
}

func TestLimitRulesCatalogNeverReadsUsageOrMutatesRuntime(t *testing.T) {
	registerBehaviorReadProbe(t)
	a, sub := subscriptionFixture(t)
	t.Cleanup(a.Close)
	probeBehaviorLedgerReads(t, a, sub)
	ctx := context.Background()
	admin, err := a.DB.UserByID(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.Signer.Issue(admin.ID, admin.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]store.Record{}
	for _, collection := range []string{"_limitState", "_quotaState", "_effectiveLimits", "_limitEvents"} {
		before[collection], _ = a.DB.ListRecords(ctx, collection, "")
	}
	r := controllerRequest(t, a.Handler(), "GET", "/api/limits/rules", token, nil)
	requireStatus(t, r, 200)
	if reads := behaviorLedgerReads.Load(); reads != 0 {
		t.Fatalf("catalog performed %d accounting reads", reads)
	}
	for collection, old := range before {
		after, err := a.DB.ListRecords(ctx, collection, "")
		left, _ := json.Marshal(old)
		right, _ := json.Marshal(after)
		if err != nil || string(left) != string(right) {
			t.Fatalf("catalog mutated %s: %v", collection, err)
		}
	}
}
