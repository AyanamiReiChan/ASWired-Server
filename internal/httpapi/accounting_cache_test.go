package httpapi

import (
	"context"
	"testing"
	"time"
)

func TestAccountingZeroDeltaAdvancesBehaviorAndCursor(t *testing.T) {
	a, sub, key, _ := limitFixture(t, []map[string]any{{"id": "sustained", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 10, "limitMbps": 2, "penaltySeconds": 30}})
	ctx := context.Background()
	start := time.Now().UnixMilli()
	for _, at := range []int64{start, start + 1000} {
		a.accountStats(ctx, "server", map[string]any{"timestamp": at, "generation": "g1", "counters": map[string]any{key: int64(100)}})
	}
	var sampled, count int64
	if err := a.DB.DB().QueryRow(`SELECT sampled_at FROM traffic_cursors WHERE server_id='server' AND counter_key=?`, key).Scan(&sampled); err != nil || sampled != start+1000 {
		t.Fatalf("cursor did not advance: %d %v", sampled, err)
	}
	if err := a.DB.DB().QueryRow(`SELECT COUNT(*) FROM traffic_ledger`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("zero delta inserted a ledger row: %d %v", count, err)
	}
	state, err := a.DB.GetRecord(ctx, "_limitState", "server/"+sub.OwnerID)
	if err != nil || readBehaviorState(state.Data).At != start+1000 || readBehaviorState(state.Data).SampleMbps != 0 {
		t.Fatalf("zero delta skipped behavior evaluation: %+v %v", state, err)
	}
}

func TestAccountingRetriesDisplayWithoutNewTraffic(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	a.expireSubscriptions(ctx) // Settle initial status and cycle metadata.
	if _, err := a.DB.DB().Exec(`CREATE TRIGGER reject_usage_display BEFORE UPDATE ON records WHEN NEW.collection='subscriptions' BEGIN SELECT RAISE(ABORT,'test display write failure'); END`); err != nil {
		t.Fatal(err)
	}
	key := "user>>>" + text(sub.Data, "credentialEmail") + ">>>traffic>>>downlink"
	a.accountStats(ctx, "server", map[string]any{"timestamp": time.Now().UnixMilli(), "generation": "g1", "counters": map[string]any{key: int64(123)}})
	before, err := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if err != nil || number(before.Data, "usedBytes") != 0 {
		t.Fatalf("failure injection did not retain old display: %v", err)
	}
	if _, err := a.DB.DB().Exec(`DROP TRIGGER reject_usage_display`); err != nil {
		t.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	after, err := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if err != nil || number(after.Data, "usedBytes") != 369 || number(after.Data, "downloadBytes") != 369 {
		t.Fatalf("maintenance did not repair display: %+v %v", after.Data, err)
	}
	// Warm usage must not hide newly committed quota exhaustion.
	plan, err := a.DB.GetRecord(ctx, "plans", "plan")
	if err != nil {
		t.Fatal(err)
	}
	plan.Data["limit"] = float64(370) / gib
	if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	// Subscription quota is frozen at issuance; update its configured quota.
	after.Data["limit"] = float64(370) / gib
	if err := a.subscriptionActive(ctx, after); err != nil {
		t.Fatalf("below quota: %v", err)
	}
	a.accountStats(ctx, "server", map[string]any{"timestamp": time.Now().Add(time.Second).UnixMilli(), "generation": "g1", "counters": map[string]any{key: int64(124)}})
	if err := a.subscriptionActive(ctx, after); err == nil {
		t.Fatal("cached usage hid quota exhaustion")
	}
}
