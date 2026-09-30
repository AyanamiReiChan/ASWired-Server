package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"modernc.org/sqlite"
)

func TestTrafficPoolReusesIncrementalWindowsAlongsidePersonalCycles(t *testing.T) {
	trafficWindowProbeOnce.Do(func() {
		if err := sqlite.RegisterScalarFunction("test_traffic_window_read", 1, func(_ *sqlite.FunctionContext, values []driver.Value) (driver.Value, error) {
			trafficWindowProbeReads.Add(1)
			return values[0], nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	s, _ := usageStore(t)
	ctx := context.Background()
	_, err := s.SaveRecord(ctx, Record{Collection: "_trafficPools", ID: "pool", Data: map[string]any{"cycleStart": time.UnixMilli(0).UTC().Format(time.RFC3339Nano), "cycleEnd": "", "members": map[string]any{"a": time.UnixMilli(0).UTC().Format(time.RFC3339Nano), "b": time.UnixMilli(100_000).UTC().Format(time.RFC3339Nano)}}})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5000 {
		usageExec(t, tx, insertNodeUsageRow, fmt.Sprint(i), []string{"a", "b"}[i%2], "email", "downlink", 1.3, i*1000)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	usageExec(t, s.db, `ALTER TABLE traffic_ledger RENAME TO traffic_pool_probe_ledger`)
	usageExec(t, s.db, `CREATE VIEW traffic_ledger AS SELECT rowid,id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,test_traffic_window_read(weighted_bytes) AS weighted_bytes,sampled_at,gap,gap_reason FROM traffic_pool_probe_ledger`)
	for _, id := range []string{"a", "b"} {
		if _, err := s.SubscriptionUsage(ctx, id, 500_000, math.MaxInt64); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.TrafficPoolUsage(ctx, "pool", math.MaxInt64); err != nil {
		t.Fatal(err)
	}
	trafficWindowProbeReads.Store(0)
	for i := range 10 {
		usageExec(t, s.db, strings.Replace(insertNodeUsageRow, "traffic_ledger", "traffic_pool_probe_ledger", 1), fmt.Sprint(5000+i), []string{"a", "b"}[i%2], "email", "downlink", 1.3, 5_000_000+i*1000)
		for _, id := range []string{"a", "b"} {
			if _, err := s.SubscriptionUsage(ctx, id, 500_000, math.MaxInt64); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.TrafficPoolUsage(ctx, "pool", math.MaxInt64); err != nil {
			t.Fatal(err)
		}
	}
	if reads := trafficWindowProbeReads.Load(); reads == 0 || reads > 700 {
		t.Fatalf("two windows thrashed historical cache: %d row reads for 10 updates", reads)
	}
	// Corrections must still invalidate frozen prefixes; shared accounting is
	// rebuilt from source rows, not an irreversible running counter.
	usageExec(t, s.db, `UPDATE traffic_pool_probe_ledger SET weighted_bytes=41 WHERE id='0'`)
	pool, err := s.TrafficPoolUsage(ctx, "pool", math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	left, err := s.queryTrafficUsage(ctx, s.db, "a", 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	right, err := s.queryTrafficUsage(ctx, s.db, "b", 100_000, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if pool.Total != left.Total+right.Total {
		t.Fatalf("correction left pool stale: %+v, %v", pool, left.Total+right.Total)
	}
}

func TestTrafficPoolConcurrentCreationAndRollback(t *testing.T) {
	s, _ := usageStore(t)
	ctx := context.Background()
	plan, err := s.SaveRecord(ctx, Record{Collection: "plans", ID: "pool", Data: map[string]any{"trafficMode": "shared"}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Format(time.RFC3339Nano)
	pool, _, err := s.SaveTrafficPool(ctx, Record{Collection: "_trafficPools", ID: "pool", Data: map[string]any{"cycleStart": start, "cycleEnd": ""}}, true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprint(i)
			_, err := s.SaveRecord(ctx, Record{Collection: "subscriptions", ID: id, OwnerID: id, Data: map[string]any{"planId": plan.ID, "cycleStart": start}})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	pool, err = s.GetRecord(ctx, "_trafficPools", "pool")
	if err != nil || len(pool.Data["members"].(map[string]any)) != 12 {
		t.Fatal("concurrent join lost windows", pool, err)
	}
	// A subsequent conflict must roll back its earlier pool registration.
	_, err = s.CompareAndSaveRecords(ctx, []Record{{Collection: "subscriptions", ID: "rollback", OwnerID: "new-user", Data: map[string]any{"planId": "pool", "cycleStart": start}}, {Collection: "plans", ID: "pool", Version: plan.Version + 100, Data: plan.Data}})
	if err != ErrConflict {
		t.Fatal("expected transactional conflict", err)
	}
	pool, _ = s.GetRecord(ctx, "_trafficPools", "pool")
	if pool.Data["members"].(map[string]any)["rollback"] != nil {
		t.Fatal("rolled-back join changed pool")
	}
	pool.Data["members"] = "invalid"
	if _, err := s.SaveRecord(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrafficPoolUsage(ctx, "pool", math.MaxInt64); err == nil {
		t.Fatal("corrupt membership silently returned an empty pool")
	}
}
