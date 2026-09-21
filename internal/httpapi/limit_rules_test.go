package httpapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func TestNodeLimitOverridesRejectInvalidNumbers(t *testing.T) {
	for _, limits := range []map[string]any{{"speed": -1}, {"connectionLimit": 1.5}, {"ipLimit": "unlimited"}, {"nodeLimits": map[string]any{"node": map[string]any{"ipLimit": -1}}}, {"nodeLimits": map[string]any{"node": map[string]any{"unsupported": 1}}}} {
		if validateLimitConfiguration(limits) == nil {
			t.Fatalf("accepted invalid limits %+v", limits)
		}
	}
	if err := validateLimitConfiguration(map[string]any{"speed": nil, "ipLimit": 0, "nodeLimits": map[string]any{"node": map[string]any{"speed": 0, "connectionLimit": 2}}}); err != nil {
		t.Fatal(err)
	}
}

func limitFixture(t *testing.T, rules []map[string]any) (*App, store.Record, string, map[string]trafficOwner) {
	t.Helper()
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	inboundData := realityInboundFixtureData()
	inboundData["name"], inboundData["tag"], inboundData["publicKey"] = "Native", "native-tag", text(realityClientFixtureData(), "publicKey")
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "native", Data: inboundData})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.peers["server"] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"shared_rate_limit": true}}
	a.mu.Unlock()
	if err := a.DB.SetSetting(ctx, "settings", map[string]any{"behaviorLimits": map[string]any{"enabled": true, "maxGapSeconds": 15, "rules": rules}}); err != nil {
		t.Fatal(err)
	}
	email := text(sub.Data, "credentialEmail") + ".native"
	return a, sub, "user>>>" + email + ">>>traffic>>>downlink", map[string]trafficOwner{email: {SubscriptionID: sub.ID, UserID: sub.OwnerID, Factor: 1}}
}

func ruleSample(a *App, key string, owners map[string]trafficOwner, at time.Time, total int64, generation string) {
	a.evaluateBehavior(context.Background(), "server", map[string]any{"timestamp": at.UnixMilli(), "generation": generation, "reset": false, "counters": map[string]any{key: total}}, owners)
}

func TestSustainedRulesTriggerOnceReleaseAndApplyRealPolicy(t *testing.T) {
	a, sub, key, owners := limitFixture(t, []map[string]any{{"id": "sustained", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30, "notify": true}})
	ctx := context.Background()
	start := time.Now().Add(-15 * time.Second)
	ruleSample(a, key, owners, start, 0, "generation-1")
	ruleSample(a, key, owners, start.Add(5*time.Second), 5_000_000, "generation-1")
	events, _ := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 0 {
		t.Fatal("triggered before duration")
	}
	ruleSample(a, key, owners, start.Add(10*time.Second), 10_000_000, "generation-1")
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 1 || text(events[0].Data, "reason") != "sustained" {
		t.Fatalf("missing exact-threshold sustained trigger: %v", events)
	}
	stateRecord, _ := a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	state := readBehaviorState(stateRecord.Data)
	until := state.Rules["global/sustained"].Until
	ruleSample(a, key, owners, start.Add(10*time.Second), 10_000_000, "generation-1")
	ruleSample(a, key, owners, start.Add(15*time.Second), 20_000_000, "generation-1")
	stateRecord, _ = a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	if readBehaviorState(stateRecord.Data).Rules["global/sustained"].Until != until {
		t.Fatal("repeated high samples extended punishment")
	}
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 1 {
		t.Fatal("repeated trigger event")
	}
	syncState, _ := a.DB.GetRecord(ctx, "_policySync", "server")
	task, err := a.DB.GetTask(ctx, text(syncState.Data, "taskId"))
	if err != nil {
		t.Fatal(err)
	}
	var command agentwire.Command
	if json.Unmarshal(task.Input, &command) != nil {
		t.Fatal("invalid policy task")
	}
	raw, _ := json.Marshal(command.Params["policies"])
	var policies []map[string]any
	json.Unmarshal(raw, &policies)
	found := false
	for _, policy := range policies {
		if text(policy, "user_id") == sub.OwnerID {
			found = true
			if number(policy, "bytes_per_second") != 250000 || text(policy, "direction") != "download" {
				t.Fatalf("real Agent policy missing: %v", policy)
			}
		}
	}
	if !found {
		t.Fatal("active policy not queued")
	}
	notices, _ := a.DB.ListRecords(ctx, "_notificationEvents", sub.OwnerID)
	if len(notices) != 1 || text(notices[0].Data, "event") != "limit.trigger" {
		t.Fatal("independent trigger notice not queued")
	}
	if !a.expireLimitPenalties(ctx, time.UnixMilli(until)) {
		t.Fatal("penalty did not release at deadline")
	}
	a.reconcilePolicies(ctx, store.User{ID: "admin", Role: "admin"})
	effective, _ := a.DB.GetRecord(ctx, "_effectiveLimits", "server/"+sub.OwnerID)
	if boolean(effective.Data, "behaviorActive") {
		t.Fatal("expired cap retained")
	}
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 2 || text(events[1].Data, "reason") != "penalty_expired" {
		t.Fatal("release reason missing")
	}
}

func TestSustainedLowSampleAndGapResetContinuity(t *testing.T) {
	a, sub, key, owners := limitFixture(t, []map[string]any{{"id": "s", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30}})
	ctx := context.Background()
	start := time.Now().Add(-40 * time.Second)
	for _, sample := range []struct {
		seconds int
		bytes   int64
	}{{0, 0}, {5, 5_000_000}, {10, 5_000_000}, {15, 10_000_000}, {35, 30_000_000}, {40, 35_000_000}} {
		ruleSample(a, key, owners, start.Add(time.Duration(sample.seconds)*time.Second), sample.bytes, "g")
	}
	events, _ := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 0 {
		t.Fatal("low sample or missing gap did not reset sustained window")
	}
	ruleSample(a, key, owners, start.Add(45*time.Second), 40_000_000, "g")
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 1 {
		t.Fatal("continuous post-gap samples did not trigger")
	}
}

func TestBurstWindowPriorityAndUserOverride(t *testing.T) {
	rules := []map[string]any{{"id": "burst", "type": "burst", "thresholdMbps": 8, "windowSeconds": 10, "hits": 2, "limitMbps": 3, "penaltySeconds": 30, "priority": 1}, {"id": "sustained", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 5, "limitMbps": 1, "penaltySeconds": 30, "priority": 20}}
	a, sub, key, owners := limitFixture(t, rules)
	ctx := context.Background()
	start := time.Now().Add(-15 * time.Second)
	ruleSample(a, key, owners, start, 0, "g")
	ruleSample(a, key, owners, start.Add(5*time.Second), 5_000_000, "g")
	ruleSample(a, key, owners, start.Add(10*time.Second), 10_000_000, "g")
	effective, details := a.behaviorEffective(ctx, sub.OwnerID, "server", effectiveLimit{10, true}, start.Add(10*time.Second))
	if effective.Value != 3 || text(details, "ruleId") != "global/burst" {
		t.Fatalf("explicit priority not used: %v", details)
	}
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "members", ID: sub.OwnerID, OwnerID: sub.OwnerID, Data: map[string]any{"behaviorLimits": map[string]any{"enabled": false}}})
	if err != nil {
		t.Fatal(err)
	}
	if !a.expireLimitPenalties(ctx, start.Add(11*time.Second)) {
		t.Fatal("user override did not release policies without new traffic")
	}
	effective, _ = a.behaviorEffective(ctx, sub.OwnerID, "server", effectiveLimit{10, true}, start.Add(11*time.Second))
	if effective.Value != 10 {
		t.Fatal("user disabled override did not restore base")
	}
	notices, _ := a.DB.ListRecords(ctx, "_notificationEvents", sub.OwnerID)
	if len(notices) != 0 {
		t.Fatal("disabled behavior notification ignored")
	}
}

func TestQuotaThrottleRestoreAndUnavailableEnforcementStops(t *testing.T) {
	a, sub, key, _ := limitFixture(t, nil)
	ctx := context.Background()
	sub.Data["limit"] = float64(100) / gib
	sub.Data["quotaMode"] = "throttle"
	sub.Data["quotaSpeedMbps"] = 2
	sub, err := a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	a.accountStats(ctx, "server", map[string]any{"timestamp": time.Now().UnixMilli(), "generation": "g", "reset": false, "counters": map[string]any{key: int64(100)}})
	if err := a.subscriptionActive(ctx, sub); err != nil {
		t.Fatal("configured quota throttle revoked whole instance")
	}
	a.reconcileUsers(ctx, store.User{ID: "admin", Role: "admin"})
	effective, _ := a.DB.GetRecord(ctx, "_effectiveLimits", "server/"+sub.OwnerID)
	if number(effective.Data, "effectiveMbps") != 2 {
		t.Fatalf("quota cap absent: %v", effective.Data)
	}
	a.mu.Lock()
	a.peers["server"].Capabilities["shared_rate_limit"] = false
	a.mu.Unlock()
	nodes, err := a.eligibleNodes(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatal("quota exceeded instance admitted without enforcement")
	}
	a.mu.Lock()
	a.peers["server"].Capabilities["shared_rate_limit"] = true
	a.mu.Unlock()
	sub, _ = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	sub.Data["limit"] = 1
	sub, err = a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	a.reconcileUsers(ctx, store.User{ID: "admin", Role: "admin"})
	effective, _ = a.DB.GetRecord(ctx, "_effectiveLimits", "server/"+sub.OwnerID)
	if number(effective.Data, "effectiveMbps") != 0 {
		t.Fatal("quota expansion failed to restore unlimited base")
	}
	events, _ := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 2 {
		t.Fatalf("quota trigger/release events missing: %d", len(events))
	}
}

func TestBurstWindowExcludesBoundaryAndGenerationResetsEvidence(t *testing.T) {
	a, sub, key, owners := limitFixture(t, []map[string]any{{"id": "burst", "type": "burst", "thresholdMbps": 8, "windowSeconds": 10, "hits": 2, "limitMbps": 1, "penaltySeconds": 30}})
	ctx := context.Background()
	start := time.Now().Add(-25 * time.Second)
	ruleSample(a, key, owners, start, 0, "g1")
	ruleSample(a, key, owners, start.Add(5*time.Second), 5_000_000, "g1")
	ruleSample(a, key, owners, start.Add(10*time.Second), 5_000_000, "g1")
	ruleSample(a, key, owners, start.Add(15*time.Second), 10_000_000, "g1")
	events, _ := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 0 {
		t.Fatal("burst counted sample on excluded window boundary")
	}
	ruleSample(a, key, owners, start.Add(20*time.Second), 5_000_000, "g2")
	ruleSample(a, key, owners, start.Add(25*time.Second), 10_000_000, "g2")
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 0 {
		t.Fatal("core restart retained pre-restart burst evidence")
	}
	ruleSample(a, key, owners, start.Add(30*time.Second), 15_000_000, "g2")
	events, _ = a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
	if len(events) != 1 {
		t.Fatal("valid new-generation burst did not trigger")
	}
}
