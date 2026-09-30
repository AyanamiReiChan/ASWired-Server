package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestBehaviorServerScopeMatchesSubscriptionEligibility(t *testing.T) {
	for _, scenario := range []struct {
		name string
		want bool
	}{
		{"eligible", true},
		{"imported node", true},
		{"invalid imported node", false},
		{"plan node scope", false},
		{"subscription node scope", false},
		{"private node excluded", false},
		{"foreign owner", false},
		{"disabled source", false},
		{"foreign source", false},
		{"missing source", false},
		{"disabled node", false},
		{"disabled inbound", false},
		{"invalid inbound", false},
		{"invalid projection", false},
		{"missing credential", false},
		{"invalid relay", false},
		{"stale relay ignored", true},
		{"disabled subscription", false},
		{"disabled member", false},
		{"expired subscription", false},
		{"disabled plan", false},
		{"node quota reached", false},
		{"node quota below", true},
		{"subscription quota reached", false},
		{"subscription quota throttle", true},
		{"subscription quota unsupported throttle", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			a, sub, _, _ := limitFixture(t, nil)
			ctx := context.Background()
			save := func(record store.Record) store.Record {
				t.Helper()
				saved, err := a.DB.SaveRecord(ctx, record)
				if err != nil {
					t.Fatal(err)
				}
				return saved
			}
			plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
			node, _ := a.DB.GetRecord(ctx, "nodes", "inbound-native")
			inbound, _ := a.DB.GetRecord(ctx, "inbounds", "native")
			switch scenario.name {
			case "imported node", "invalid imported node":
				node.Data = realityClientFixtureData()
				node.Data["serverId"] = "server"
				if scenario.name == "invalid imported node" {
					node.Data["publicKey"] = "invalid"
				}
			case "plan node scope":
				plan.Data["nodeIds"] = []string{"ss-node"}
			case "subscription node scope":
				sub.Data["nodeIds"] = []string{"ss-node"}
			case "private node excluded":
				node.OwnerID = sub.OwnerID
				sub.Data["includePrivateNodes"] = false
			case "foreign owner":
				node.OwnerID = "someone-else"
			case "disabled source", "foreign source":
				node.Data["sourceId"] = "source"
				source := store.Record{Collection: "sources", ID: "source", Data: map[string]any{}}
				if scenario.name == "disabled source" {
					source.Data["status"] = "禁用"
				} else {
					source.OwnerID = "someone-else"
				}
				save(source)
			case "missing source":
				node.Data["sourceId"] = "missing"
			case "disabled node":
				node.Data["status"] = "禁用"
			case "disabled inbound":
				inbound.Data["status"] = "禁用"
			case "invalid inbound":
				inbound.Data["protocol"] = "unsupported"
			case "invalid projection":
				node.Data["host"] = ""
			case "missing credential":
				sub.Data["credentialUUID"] = ""
			case "invalid relay", "stale relay ignored":
				original := "127.0.0.1:443"
				if scenario.name == "stale relay ignored" {
					original = "192.0.2.1:443"
				}
				save(store.Record{Collection: "relays", ID: node.ID, Data: map[string]any{"originalAddress": original, "relayAddress": "invalid"}})
			case "disabled subscription":
				sub.Data["status"] = "禁用"
			case "disabled member":
				user, err := a.DB.UserByID(ctx, sub.OwnerID)
				if err != nil {
					t.Fatal(err)
				}
				user.Disabled = true
				if err := a.DB.UpdateUser(ctx, user); err != nil {
					t.Fatal(err)
				}
			case "expired subscription":
				sub.Data["expires"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
			case "disabled plan":
				plan.Data["status"] = "禁用"
			case "node quota reached", "node quota below":
				limit := 1.0
				if scenario.name == "node quota below" {
					limit = 2
				}
				plan.Data["nodeTraffic"] = map[string]any{node.ID: map[string]any{"limit": limit}}
			case "subscription quota reached", "subscription quota throttle", "subscription quota unsupported throttle":
				sub.Data["limit"] = 1
				if scenario.name != "subscription quota reached" {
					plan.Data["quotaMode"], plan.Data["quotaSpeedMbps"] = "throttle", 2
					if scenario.name == "subscription quota unsupported throttle" {
						a.peers["server"].Capabilities = map[string]bool{}
					}
				}
			}
			plan = save(plan)
			sub = save(sub)
			save(node)
			save(inbound)
			if _, err := a.DB.DB().Exec(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES('scope-usage','server',?,?,?,'downlink',?,1,?,?,0,'')`, sub.ID, sub.OwnerID, text(sub.Data, "credentialEmail")+".native", int64(gib), gib, time.Now().UnixMilli()); err != nil {
				t.Fatal(err)
			}
			// The subscription path remains the reference for profile, relay,
			// ownership and quota decisions; behavior must select the same server.
			expected := false
			nodes, err := a.eligibleNodes(ctx, sub)
			if err == nil {
				for _, candidate := range nodes {
					expected = expected || text(candidate.Data, "serverId") == "server"
				}
			}
			cfg, err := a.behaviorFor(ctx, sub.OwnerID, "server")
			if err != nil || cfg.Enabled != expected || expected != scenario.want {
				t.Fatalf("behavior enabled=%v, subscription eligible=%v, want=%v, error=%v", cfg.Enabled, expected, scenario.want, err)
			}
		})
	}
}

func TestBehaviorScopeRefreshesBetweenReports(t *testing.T) {
	a, sub, key, owners := limitFixture(t, nil)
	ctx := context.Background()
	start := time.Now()
	ruleSample(a, key, owners, start, 0, "generation")
	before, err := a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeIds"] = []string{"ss-node"}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	ruleSample(a, key, owners, start.Add(time.Second), 0, "generation")
	after, err := a.DB.GetRecord(ctx, "_limitState", before.ID)
	if err != nil {
		t.Fatal(err)
	}
	state := readBehaviorState(after.Data)
	if state.PolicyHash == readBehaviorState(before.Data).PolicyHash || !state.SampleValid || state.SampleMbps != 0 {
		t.Fatalf("new report reused old scope or lost its valid zero sample: %+v", state)
	}
}

func TestBehaviorChecksOnlyCurrentServerNodeQuotas(t *testing.T) {
	registerBehaviorReadProbe(t)
	a, sub, _, _ := limitFixture(t, nil)
	ctx := context.Background()
	other := realityClientFixtureData()
	other["serverId"], other["managedInbound"], other["inboundId"] = "other-server", true, "other-inbound"
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "nodes", ID: "other-node", Data: other}); err != nil {
		t.Fatal(err)
	}
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["nodeTraffic"] = map[string]any{"other-node": map[string]any{"limit": 1000}}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	probeBehaviorLedgerReads(t, a, sub)
	if _, err := a.DB.DB().Exec(`UPDATE behavior_probe_ledger SET email=?`, text(sub.Data, "credentialEmail")+".other-inbound"); err != nil {
		t.Fatal(err)
	}
	// Warm the subscription total only. A quota SUM for the unrelated node
	// would still touch the probed ledger value after this reset.
	if _, _, _, err := a.subscriptionUsage(ctx, sub); err != nil {
		t.Fatal(err)
	}
	behaviorLedgerReads.Store(0)
	cfg, err := a.behaviorFor(ctx, sub.OwnerID, "server")
	if err != nil || !cfg.Enabled || behaviorLedgerReads.Load() != 0 {
		t.Fatalf("unrelated server quota scanned: config=%+v, reads=%d, error=%v", cfg, behaviorLedgerReads.Load(), err)
	}
	if _, err := a.planNodeQuotaExceeded(ctx, sub, plan.Data, "other-node", "other-inbound"); err != nil || behaviorLedgerReads.Load() == 0 {
		t.Fatalf("probe failed to detect unrelated quota SUM: reads=%d, error=%v", behaviorLedgerReads.Load(), err)
	}
}
