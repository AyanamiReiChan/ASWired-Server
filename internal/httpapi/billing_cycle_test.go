package httpapi

import (
	"context"
	"testing"
	"time"
)

func TestCyclePolicyEditsPreserveCurrentUsageStart(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil {
		t.Fatal(err)
	}
	start := text(sub.Data, "cycleStart")
	plan.Data["reset"] = "不重置"
	plan, err = a.DB.SaveRecord(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	sub, _ = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if text(sub.Data, "cycleEnd") != "" || text(sub.Data, "cycleStart") != start {
		t.Fatal("no-reset policy lost current cycle", sub.Data)
	}
	plan.Data["reset"] = "每月指定日"
	plan.Data["resetDay"] = 22
	plan.Data["resetTimezone"] = "Asia/Shanghai"
	plan, err = a.DB.SaveRecord(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	sub, _ = a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	want := cycleStamp(nextCycleEnd(cyclePolicy(plan.Data, sub.Data), time.Now().UTC()))
	if text(sub.Data, "cycleStart") != start || text(sub.Data, "cycleEnd") != want {
		t.Fatal("policy edit did not recalculate next reset without clearing usage", sub.Data)
	}
}

func TestMonthlyCycleClampsAndRestoresDay(t *testing.T) {
	policy := map[string]any{"reset": "每月指定日", "resetDay": 31, "resetTimezone": "Asia/Shanghai"}
	start, _ := time.Parse(time.RFC3339, "2028-01-31T00:00:00+08:00")
	end := nextCycleEnd(policy, start)
	if end.Format(time.RFC3339) != "2028-02-28T16:00:00Z" {
		t.Fatalf("leap February boundary: %s", end)
	}
	end = nextCycleEnd(policy, end)
	if end.Format(time.RFC3339) != "2028-03-30T16:00:00Z" {
		t.Fatalf("March must restore day 31: %s", end)
	}
}

func TestMonthlyCycleCanEndLaterInCurrentMonth(t *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2026-09-19T12:00:00+08:00")
	policy := cyclePolicy(map[string]any{"reset": "每月 1 日"}, map[string]any{"resetDay": 22, "resetTimezone": "Asia/Shanghai"})
	if got := nextCycleEnd(policy, start).Format(time.RFC3339); got != "2026-09-21T16:00:00Z" {
		t.Fatal(got)
	}
}

func TestCycleValidationAndNoReset(t *testing.T) {
	for _, policy := range []map[string]any{{"resetDay": 0}, {"resetDay": 32}, {"resetDay": 1.5}, {"resetTimezone": "invalid/timezone"}} {
		if validateCyclePolicy(policy) == nil {
			t.Fatalf("accepted invalid policy %v", policy)
		}
	}
	if !nextCycleEnd(map[string]any{"reset": "不重置", "cycleDays": 30}, time.Now()).IsZero() {
		t.Fatal("no-reset policy has a cycle end")
	}
}
