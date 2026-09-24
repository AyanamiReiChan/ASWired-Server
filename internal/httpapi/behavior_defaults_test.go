package httpapi

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestBehaviorDefaultPolicyPreservesExplicitOverrides(t *testing.T) {
	custom := map[string]any{"enabled": true, "rules": []map[string]any{{"id": "custom", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30}}}
	for _, item := range []struct {
		name         string
		settings     map[string]any
		plan, member any
		wantEnabled  bool
		wantRules    int
		wantSource   string
	}{
		{name: "missing global", settings: map[string]any{}, wantEnabled: true, wantRules: 2, wantSource: "global"},
		{name: "null global", settings: map[string]any{"behaviorLimits": nil}, wantEnabled: true, wantRules: 2, wantSource: "global"},
		{name: "disabled global", settings: map[string]any{"behaviorLimits": map[string]any{"enabled": false}}},
		{name: "empty global object", settings: map[string]any{"behaviorLimits": map[string]any{}}, wantEnabled: true},
		{name: "empty global rules", settings: map[string]any{"behaviorLimits": map[string]any{"enabled": true, "rules": []any{}}}, wantEnabled: true},
		{name: "custom global", settings: map[string]any{"behaviorLimits": custom}, wantEnabled: true, wantRules: 1, wantSource: "global"},
		{name: "disabled plan", settings: map[string]any{}, plan: map[string]any{"enabled": false}},
		{name: "empty plan rules", settings: map[string]any{}, plan: map[string]any{"rules": []any{}}, wantEnabled: true},
		{name: "custom plan", settings: map[string]any{}, plan: custom, wantEnabled: true, wantRules: 1, wantSource: "plan:plan"},
		{name: "disabled member", settings: map[string]any{}, plan: custom, member: map[string]any{"enabled": false}},
		{name: "custom member", settings: map[string]any{}, plan: map[string]any{"enabled": false}, member: custom, wantEnabled: true, wantRules: 1, wantSource: "member:"},
	} {
		t.Run(item.name, func(t *testing.T) {
			a, sub, _, _ := limitFixture(t, nil)
			ctx := context.Background()
			if err := a.DB.SetSetting(ctx, "settings", item.settings); err != nil {
				t.Fatal(err)
			}
			if item.plan != nil {
				saveBehaviorPlan(t, a, sub, item.plan)
			}
			if item.member != nil {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "members", ID: sub.OwnerID, OwnerID: sub.OwnerID, Data: map[string]any{"behaviorLimits": item.member}}); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := a.behaviorFor(ctx, sub.OwnerID, "server")
			if err != nil || cfg.Enabled != item.wantEnabled || len(cfg.Rules) != item.wantRules {
				t.Fatalf("override changed: %+v, %v", cfg, err)
			}
			wantSource := item.wantSource
			if wantSource == "member:" {
				wantSource += sub.OwnerID
			}
			for _, rule := range cfg.Rules {
				if rule.Source != wantSource {
					t.Fatalf("wrong rule source: %+v", rule)
				}
			}
			var saved map[string]any
			if err := a.DB.GetSetting(ctx, "settings", &saved); err != nil {
				t.Fatal(err)
			}
			if _, originallyPresent := item.settings["behaviorLimits"]; !originallyPresent {
				if _, nowPresent := saved["behaviorLimits"]; nowPresent {
					t.Fatal("runtime default unexpectedly rewrote stored settings")
				}
			} else if item.settings["behaviorLimits"] == nil && saved["behaviorLimits"] != nil {
				t.Fatal("runtime default unexpectedly replaced stored null")
			}
		})
	}
}

func TestBehaviorDefaultPolicyValuesAreIndependent(t *testing.T) {
	first := defaultBehaviorLimits()
	first["enabled"] = false
	first["rules"].([]map[string]any)[0]["limitMbps"] = 999
	second := defaultBehaviorLimits()
	cfg, err := behaviorConfiguration(second, "global")
	if err != nil || !cfg.Enabled || cfg.MaxGapSeconds != 15 || len(cfg.Rules) != 2 {
		t.Fatalf("default configuration invalid or shared: %+v, %v", cfg, err)
	}
	want := []behaviorRule{
		{ID: "global/balanced-long", Type: "sustained", ThresholdMbps: 80, DurationSeconds: 600, LimitMbps: 30, PenaltySeconds: 600, Priority: 10, Source: "global"},
		{ID: "global/balanced-high", Type: "sustained", ThresholdMbps: 200, DurationSeconds: 120, LimitMbps: 50, PenaltySeconds: 600, Priority: 20, Source: "global"},
	}
	if !reflect.DeepEqual(cfg.Rules, want) {
		t.Fatalf("default policy drift: %+v", cfg.Rules)
	}
}

func TestBehaviorDefaultsAllowShortBurstsThenTriggerAndExpire(t *testing.T) {
	for _, item := range []struct {
		name, ruleID string
		mbps, limit  float64
		seconds      int
	}{
		{name: "high rate", ruleID: "global/balanced-high", mbps: 200, limit: 50, seconds: 120},
		{name: "long download", ruleID: "global/balanced-long", mbps: 80, limit: 30, seconds: 600},
	} {
		t.Run(item.name, func(t *testing.T) {
			a, sub, key, owners := limitFixture(t, nil)
			ctx := context.Background()
			if err := a.DB.SetSetting(ctx, "settings", map[string]any{}); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			total := int64(0)
			ruleSample(a, key, owners, start, total, "g")
			// An initial 30-second video/download burst is interrupted by a low
			// sample. It must not shorten the next sustained interval.
			for seconds := 5; seconds <= 30; seconds += 5 {
				total += int64(item.mbps * 1e6 / 8 * 5)
				ruleSample(a, key, owners, start.Add(time.Duration(seconds)*time.Second), total, "g")
			}
			ruleSample(a, key, owners, start.Add(35*time.Second), total, "g")
			start = start.Add(35 * time.Second)
			for seconds := 5; seconds < item.seconds; seconds += 5 {
				total += int64(item.mbps * 1e6 / 8 * 5)
				ruleSample(a, key, owners, start.Add(time.Duration(seconds)*time.Second), total, "g")
			}
			events, err := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
			if err != nil || len(events) != 0 {
				t.Fatalf("short or interrupted download triggered: %v, %v", events, err)
			}
			total += int64(item.mbps * 1e6 / 8 * 5)
			at := start.Add(time.Duration(item.seconds) * time.Second)
			ruleSample(a, key, owners, at, total, "g")
			events, err = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
			if err != nil || len(events) != 1 || text(events[0].Data, "ruleId") != item.ruleID || text(events[0].Data, "notificationStatus") != "disabled" {
				t.Fatalf("default trigger missing or notified unexpectedly: %v, %v", events, err)
			}
			effective, details := a.behaviorEffective(ctx, sub.OwnerID, "server", effectiveLimit{1000, true}, at)
			if effective.Value != item.limit || text(details, "ruleId") != item.ruleID {
				t.Fatalf("wrong default cap: %+v, %+v", effective, details)
			}
			// Behavior caps must never raise a lower configured entitlement.
			effective, _ = a.behaviorEffective(ctx, sub.OwnerID, "server", effectiveLimit{10, true}, at)
			if effective.Value != 10 {
				t.Fatalf("default raised an existing cap: %+v", effective)
			}
			until := at.Add(600 * time.Second)
			if a.expireLimitPenalties(ctx, until.Add(-time.Millisecond)) || !a.expireLimitPenalties(ctx, until) {
				t.Fatal("default penalty did not expire at its exact deadline")
			}
		})
	}
}

func TestBehaviorDefaultMaintenanceWithoutPenaltyDoesNotReadQuota(t *testing.T) {
	registerBehaviorReadProbe(t)
	a, sub, key, owners := limitFixture(t, nil)
	ctx := context.Background()
	if err := a.DB.SetSetting(ctx, "settings", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	saveBehaviorPlan(t, a, sub, nil)
	start := time.Now()
	ruleSample(a, key, owners, start, 0, "g")
	ruleSample(a, key, owners, start.Add(5*time.Second), 125_000_000, "g")
	before, err := a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	probeBehaviorLedgerReads(t, a, sub)
	for i := range 3 {
		if a.expireLimitPenalties(ctx, start.Add(time.Duration(10+i*5)*time.Second)) {
			t.Fatal("maintenance released a nonexistent default penalty")
		}
	}
	if reads := behaviorLedgerReads.Load(); reads != 0 {
		t.Fatalf("enabled defaults restored idle quota scans: %d", reads)
	}
	after, err := a.DB.GetRecord(ctx, "_limitState", before.ID)
	if err != nil || before.Version != after.Version || !reflect.DeepEqual(before.Data, after.Data) {
		t.Fatal("idle maintenance changed sample evidence", after, err)
	}
	if _, _, _, err := a.subscriptionUsage(ctx, sub); err != nil || behaviorLedgerReads.Load() == 0 {
		t.Fatalf("ledger probe did not detect a real usage scan: %d, %v", behaviorLedgerReads.Load(), err)
	}
}
