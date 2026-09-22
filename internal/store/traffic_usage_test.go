package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
)

const insertUsageRow = `INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,'owner','email',?,1,1,?,?,0,'')`

func usageStore(t testing.TB) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "usage.db")
	s, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func usageExec(t testing.TB, db interface {
	Exec(string, ...any) (sql.Result, error)
}, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func checkUsage(t testing.TB, s *Store, id string, start, end int64, want TrafficUsage) {
	t.Helper()
	for range 2 { // Exercise both cold and warm paths.
		got, err := s.SubscriptionUsage(context.Background(), id, start, end)
		if err != nil || got != want {
			t.Fatalf("usage %q [%d,%d): got %+v, want %+v: %v", id, start, end, got, want, err)
		}
	}
}

func TestTrafficUsageInvalidation(t *testing.T) {
	s, path := usageStore(t)
	checkUsage(t, s, "a", 10, 20, TrafficUsage{})
	usageExec(t, s.db, insertUsageRow, "1", "a", "uplink", 1.25, 10)
	checkUsage(t, s, "a", 10, 20, TrafficUsage{Total: 1.25, Up: 1.25})
	// Another Store/connection can write; invalidation is not process-local.
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	usageExec(t, other.db, insertUsageRow, "2", "a", "downlink", 2.5, 19)
	checkUsage(t, s, "a", 10, 20, TrafficUsage{Total: 3.75, Up: 1.25, Down: 2.5})
	tx, err := other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `UPDATE traffic_ledger SET weighted_bytes=99 WHERE id='1'`)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	checkUsage(t, s, "a", 10, 20, TrafficUsage{Total: 3.75, Up: 1.25, Down: 2.5})
	checkUsage(t, s, "b", 10, 20, TrafficUsage{})
	usageExec(t, other.db, `UPDATE traffic_ledger SET subscription_id='b',direction='downlink',weighted_bytes=4 WHERE id='1'`)
	checkUsage(t, s, "a", 10, 20, TrafficUsage{Total: 2.5, Down: 2.5})
	checkUsage(t, s, "b", 10, 20, TrafficUsage{Total: 4, Down: 4})
	usageExec(t, other.db, `UPDATE traffic_ledger SET sampled_at=20 WHERE id='1'`)
	checkUsage(t, s, "b", 10, 20, TrafficUsage{})
	checkUsage(t, s, "b", 10, 21, TrafficUsage{Total: 4, Down: 4})
	usageExec(t, other.db, `DELETE FROM traffic_ledger WHERE id='1'`)
	checkUsage(t, s, "b", 10, 21, TrafficUsage{})
	// Logical restore deletes then reinserts inside one transaction. Revisions
	// are not restored to old values even if IDs and row counts are identical.
	tx, err = other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `DELETE FROM traffic_ledger`)
	usageExec(t, tx, insertUsageRow, "2", "a", "uplink", 8.5, 15)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkUsage(t, s, "a", 10, 20, TrafficUsage{Total: 8.5, Up: 8.5})
	checkUsage(t, other, "a", 10, 20, TrafficUsage{Total: 8.5, Up: 8.5})
	usageExec(t, other.db, `DELETE FROM traffic_ledger`)
	checkUsage(t, s, "a", 10, 20, TrafficUsage{})
}

func TestTrafficUsageIntervalsAndExactSums(t *testing.T) {
	s, _ := usageStore(t)
	for i, v := range []float64{0.1, 0.2, 1e16, 0.3, 1e-9, 2.75} {
		direction := "uplink"
		if i%2 == 0 {
			direction = "downlink"
		}
		usageExec(t, s.db, insertUsageRow, fmt.Sprint(i), "a", direction, v, 10+i)
	}
	// Bound changes include cycle resets, moving no-reset ends, imported future
	// rows and backwards clock changes. Compare float bits, not a tolerance.
	for _, bounds := range [][2]int64{{10, 20}, {10, 21}, {10, 14}, {11, 14}, {10, 15}, {10, 16}, {10, 1000}, {10, 1}, {10, 20}} {
		want, err := s.queryTrafficUsage(context.Background(), s.db, "a", bounds[0], bounds[1])
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			got, err := s.SubscriptionUsage(context.Background(), "a", bounds[0], bounds[1])
			if err != nil || math.Float64bits(got.Total) != math.Float64bits(want.Total) || math.Float64bits(got.Up) != math.Float64bits(want.Up) || math.Float64bits(got.Down) != math.Float64bits(want.Down) {
				t.Fatalf("bounds %v: %+v != %+v: %v", bounds, got, want, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SubscriptionUsage(ctx, "a", 10, 20); err == nil {
		t.Fatal("canceled request returned cached success")
	}
}

func TestTrafficUsageExistingDatabaseAndReopen(t *testing.T) {
	s, path := usageStore(t)
	for _, name := range []string{"traffic_usage_insert", "traffic_usage_update", "traffic_usage_delete"} {
		usageExec(t, s.db, `DROP TRIGGER `+name)
	}
	usageExec(t, s.db, `DROP TABLE traffic_usage_revisions`)
	usageExec(t, s.db, insertUsageRow, "old", "a", "uplink", 17.5, 10)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reopened, err := Open(Config{Driver: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		checkUsage(t, reopened, "a", 10, 20, TrafficUsage{Total: 17.5, Up: 17.5})
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTrafficUsageConcurrentSnapshots(t *testing.T) {
	s, _ := usageStore(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 80 {
				u, err := s.SubscriptionUsage(context.Background(), "a", 0, 1000)
				if err != nil || u.Up*2 != u.Down || u.Total != u.Up+u.Down {
					t.Errorf("inconsistent snapshot %+v: %v", u, err)
					return
				}
			}
		})
	}
	for i := range 40 {
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		usageExec(t, tx, insertUsageRow, fmt.Sprintf("u%d", i), "a", "uplink", 1, i)
		usageExec(t, tx, insertUsageRow, fmt.Sprintf("d%d", i), "a", "downlink", 2, i)
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	checkUsage(t, s, "a", 0, 1000, TrafficUsage{Total: 120, Up: 40, Down: 80})
}

// One operation checks all nine subscriptions three times, as maintenance and
// policy generation do. The baseline uses the unchanged legacy SUM queries.
func BenchmarkTrafficUsage82203Rows(b *testing.B) {
	s, _ := usageStore(b)
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := range 82203 {
		direction := "uplink"
		if i%2 == 0 {
			direction = "downlink"
		}
		usageExec(b, tx, insertUsageRow, fmt.Sprint(i), fmt.Sprint(i%9), direction, float64(i%1000)*1.3, i)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, mode := range []string{"legacy", "cached", "one_subscription_changed"} {
		b.Run(mode, func(b *testing.B) {
			for i := range 9 {
				if _, err := s.SubscriptionUsage(ctx, fmt.Sprint(i), 0, 100000); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if mode == "one_subscription_changed" {
					usageExec(b, s.db, `UPDATE traffic_ledger SET weighted_bytes=weighted_bytes+1 WHERE id='0'`)
				}
				for range 3 {
					for i := range 9 {
						var err error
						if mode == "legacy" {
							_, err = s.queryTrafficUsage(ctx, s.db, fmt.Sprint(i), 0, 100000)
						} else {
							_, err = s.SubscriptionUsage(ctx, fmt.Sprint(i), 0, 100000)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}
