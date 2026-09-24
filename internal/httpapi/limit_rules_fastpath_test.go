package httpapi

import (
	"context"
	"database/sql/driver"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"modernc.org/sqlite"
)

var behaviorReadRegistration sync.Once
var behaviorLedgerReads atomic.Int64

func registerBehaviorReadProbe(t *testing.T) {
	t.Helper()
	behaviorReadRegistration.Do(func() {
		if err := sqlite.RegisterScalarFunction("test_behavior_usage_read", 1, func(_ *sqlite.FunctionContext, values []driver.Value) (driver.Value, error) {
			behaviorLedgerReads.Add(1)
			return values[0], nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

// A scalar probe on the SUM input records actual ledger reads, including reads
// whose errors callers might otherwise swallow. Production code needs no hook.
func probeBehaviorLedgerReads(t *testing.T, a *App, sub store.Record) {
	t.Helper()
	if _, err := a.DB.DB().Exec(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES('behavior-probe','server',?,?,?,'downlink',1,1,1,?,0,'')`, sub.ID, sub.OwnerID, text(sub.Data, "credentialEmail")+".native", time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`ALTER TABLE traffic_ledger RENAME TO behavior_probe_ledger`,
		`CREATE VIEW traffic_ledger AS SELECT id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,test_behavior_usage_read(weighted_bytes) AS weighted_bytes,sampled_at,gap,gap_reason FROM behavior_probe_ledger`,
	} {
		if _, err := a.DB.DB().Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	behaviorLedgerReads.Store(0)
}

func saveBehaviorPlan(t *testing.T, a *App, sub store.Record, config any) {
	t.Helper()
	plan, err := a.DB.GetRecord(context.Background(), "plans", text(sub.Data, "planId"))
	if err != nil {
		t.Fatal(err)
	}
	plan.Data["behaviorLimits"] = config
	plan.Data["nodeTraffic"] = map[string]any{"inbound-native": map[string]any{"limit": 1000}}
	if _, err := a.DB.SaveRecord(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
}

func TestBehaviorDisabledSkipsQuotaReadsButKeepsSampleBaseline(t *testing.T) {
	registerBehaviorReadProbe(t)
	a, sub, key, owners := limitFixture(t, nil)
	ctx := context.Background()
	saveBehaviorPlan(t, a, sub, map[string]any{"enabled": false})
	probeBehaviorLedgerReads(t, a, sub)
	start := time.Now().Add(-time.Second)
	for i := range 2 {
		ruleSample(a, key, owners, start.Add(time.Duration(i)*time.Second), int64(100+i), "same-generation")
	}
	if reads := behaviorLedgerReads.Load(); reads != 0 {
		t.Fatalf("disabled behavior read %d ledger values", reads)
	}
	record, err := a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	state := readBehaviorState(record.Data)
	if err != nil || state.At != start.Add(time.Second).UnixMilli() || state.Counters[key] != 101 || !state.SampleValid {
		t.Fatalf("disabled behavior lost its sample baseline: %+v, %v", state, err)
	}
	// Verify that the probe actually observes a SUM; a broken probe must not
	// turn the preceding zero-read assertion into a false positive.
	if _, _, _, err := a.subscriptionUsage(ctx, sub); err != nil || behaviorLedgerReads.Load() == 0 {
		t.Fatalf("ledger probe did not detect a real SUM: %d, %v", behaviorLedgerReads.Load(), err)
	}
}

func TestBehaviorMaintenanceWithoutPenaltySkipsQuotaReads(t *testing.T) {
	registerBehaviorReadProbe(t)
	a, sub, _, _ := limitFixture(t, []map[string]any{{"id": "rule", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30}})
	ctx := context.Background()
	plan, err := a.DB.GetRecord(ctx, "plans", "plan")
	if err != nil {
		t.Fatal(err)
	}
	plan.Data["nodeTraffic"] = map[string]any{"inbound-native": map[string]any{"limit": 1000}}
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	state := behaviorState{At: time.Now().UnixMilli(), Generation: "g", PolicyHash: "old-policy", Counters: map[string]int64{"counter": 123}, Rules: map[string]behaviorProgress{"global/rule": {AboveSince: 1, Hits: []int64{2, 3}}}}
	record, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_limitState", ID: "server/" + sub.OwnerID, OwnerID: sub.OwnerID, Data: stateData(state)})
	if err != nil {
		t.Fatal(err)
	}
	queuedEvent, err := a.DB.SaveRecord(ctx, limitEvent(sub.OwnerID, "server", "global/rule", "triggered", "sustained", behaviorProgress{Until: state.At + 1000, LimitMbps: 2, Notify: true}, 8, state.At))
	if err != nil {
		t.Fatal(err)
	}
	probeBehaviorLedgerReads(t, a, sub)
	if a.expireLimitPenalties(ctx, time.Now()) {
		t.Fatal("no penalty should have been released")
	}
	if reads := behaviorLedgerReads.Load(); reads != 0 {
		t.Fatalf("maintenance without a penalty read %d ledger values", reads)
	}
	after, err := a.DB.GetRecord(ctx, "_limitState", record.ID)
	if err != nil || after.Version != record.Version || !reflect.DeepEqual(after.Data, record.Data) {
		t.Fatal("no-penalty maintenance altered baseline or partial rule evidence", after, err)
	}
	queuedEvent, err = a.DB.GetRecord(ctx, "_limitEvents", queuedEvent.ID)
	if err != nil || text(queuedEvent.Data, "notificationStatus") != "queued" {
		t.Fatal("no-penalty shortcut skipped pending event delivery", queuedEvent, err)
	}
}

func TestBehaviorMaintenanceReleasesAlreadyExpiredPenalty(t *testing.T) {
	a, sub, _, _ := limitFixture(t, nil)
	ctx := context.Background()
	saveBehaviorPlan(t, a, sub, map[string]any{"enabled": false})
	now := time.Now()
	state := behaviorState{At: now.Add(-time.Minute).UnixMilli(), Rules: map[string]behaviorProgress{"old/rule": {Until: now.Add(-time.Second).UnixMilli(), LimitMbps: 2}}}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_limitState", ID: "server/" + sub.OwnerID, OwnerID: sub.OwnerID, Data: stateData(state)}); err != nil {
		t.Fatal(err)
	}
	if !a.expireLimitPenalties(ctx, now) {
		t.Fatal("already expired positive deadline was skipped")
	}
	if a.expireLimitPenalties(ctx, now.Add(time.Second)) {
		t.Fatal("released penalty was processed twice")
	}
	events, err := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if err != nil || len(events) != 1 || text(events[0].Data, "reason") != "penalty_expired" {
		t.Fatal("expiry release missing or duplicated", events, err)
	}
}

func TestBehaviorConfigurationPriorityAndDeferredErrors(t *testing.T) {
	rule := map[string]any{"id": "plan-rule", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30}
	valid := map[string]any{"enabled": true, "rules": []any{rule}}
	for _, item := range []struct {
		name, server           string
		global, plan, member   any
		disabled               bool
		wantError, wantEnabled bool
	}{
		{name: "plan enables globally disabled rules", server: "server", global: map[string]any{"enabled": false}, plan: valid, wantEnabled: true},
		{name: "member enables globally disabled rules", server: "server", global: map[string]any{"enabled": false}, plan: map[string]any{"enabled": false}, member: valid, wantEnabled: true},
		{name: "member disabled overrides invalid global", server: "server", global: "invalid", plan: valid, member: map[string]any{"enabled": false}},
		{name: "global error remains unconditional", server: "unrelated", global: "invalid", plan: valid, wantError: true},
		{name: "relevant plan error", server: "server", global: map[string]any{"enabled": false}, plan: "invalid", wantError: true},
		{name: "unrelated plan error ignored", server: "unrelated", global: map[string]any{"enabled": false}, plan: "invalid"},
		{name: "inactive plan error ignored", server: "server", global: map[string]any{"enabled": false}, plan: "invalid", disabled: true},
		{name: "enabled empty rules retain metadata", server: "server", global: map[string]any{"enabled": false}, plan: map[string]any{"enabled": true, "maxGapSeconds": 5}, wantEnabled: true},
	} {
		t.Run(item.name, func(t *testing.T) {
			a, sub, _, _ := limitFixture(t, nil)
			ctx := context.Background()
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{"behaviorLimits": item.global}); err != nil {
				t.Fatal(err)
			}
			saveBehaviorPlan(t, a, sub, item.plan)
			if item.member != nil {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "members", ID: sub.OwnerID, OwnerID: sub.OwnerID, Data: map[string]any{"behaviorLimits": item.member}}); err != nil {
					t.Fatal(err)
				}
			}
			if item.disabled {
				sub.Data["status"] = "停用"
				if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := a.behaviorFor(ctx, sub.OwnerID, item.server)
			if (err != nil) != item.wantError || err == nil && cfg.Enabled != item.wantEnabled {
				t.Fatalf("configuration semantics changed: %+v, %v", cfg, err)
			}
			if item.name == "enabled empty rules retain metadata" && (cfg.MaxGapSeconds != 5 || len(cfg.Rules) != 0) {
				t.Fatalf("empty-rule metadata changed: %+v", cfg)
			}
		})
	}
}
