package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const insertNodeUsageRow = `INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,'owner',?,?,1,1,?,?,0,'')`
const nodeUsageSQL = `SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND email=? AND sampled_at>=? AND sampled_at<?`
const createNodeUsageIndex = `CREATE INDEX traffic_ledger_subscription_email ON traffic_ledger(subscription_id,email,sampled_at)`

func checkNodeUsage(t testing.TB, s *Store, subscriptionID, email string, start, end int64, want float64) {
	t.Helper()
	for range 2 { // Check a miss followed by a hit against the same snapshot.
		got, err := s.NodeTrafficUsage(context.Background(), subscriptionID, email, start, end)
		if err != nil || math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("node usage %q/%q [%d,%d): %v != %v: %v", subscriptionID, email, start, end, got, want, err)
		}
	}
}

func TestNodeTrafficUsageExternalInvalidationAndRestore(t *testing.T) {
	s, path := usageStore(t)
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	checkNodeUsage(t, s, "a", "one", 10, 20, 0)
	checkNodeUsage(t, s, "a", "two", 10, 20, 0)
	checkNodeUsage(t, s, "b", "two", 10, 20, 0)
	usageExec(t, other.db, insertNodeUsageRow, "1", "a", "one", "uplink", 1.25, 10)
	checkNodeUsage(t, s, "a", "one", 10, 20, 1.25)
	usageExec(t, other.db, insertNodeUsageRow, "2", "a", "one", "downlink", 2.5, 19)
	usageExec(t, other.db, insertNodeUsageRow, "different-email", "a", "other", "uplink", 99, 10)
	usageExec(t, other.db, insertNodeUsageRow, "different-sub", "other", "one", "uplink", 99, 10)
	checkNodeUsage(t, s, "a", "one", 10, 20, 3.75)
	tx, err := other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `UPDATE traffic_ledger SET weighted_bytes=100 WHERE id='1'`)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	checkNodeUsage(t, s, "a", "one", 10, 20, 3.75)
	usageExec(t, other.db, `UPDATE traffic_ledger SET email='two',weighted_bytes=4 WHERE id='1'`)
	checkNodeUsage(t, s, "a", "one", 10, 20, 2.5)
	checkNodeUsage(t, s, "a", "two", 10, 20, 4)
	usageExec(t, other.db, `UPDATE traffic_ledger SET subscription_id='b' WHERE id='1'`)
	checkNodeUsage(t, s, "a", "two", 10, 20, 0)
	checkNodeUsage(t, s, "b", "two", 10, 20, 4)
	usageExec(t, other.db, `UPDATE traffic_ledger SET sampled_at=20,weighted_bytes=5 WHERE id='1'`)
	checkNodeUsage(t, s, "b", "two", 10, 20, 0)
	checkNodeUsage(t, s, "b", "two", 10, 21, 5)
	usageExec(t, other.db, `DELETE FROM traffic_ledger WHERE id='1'`)
	checkNodeUsage(t, s, "b", "two", 10, 21, 0)
	// A logical restore can reuse row IDs and row counts. Its transactional
	// DELETE/INSERT must still invalidate all cached pairs for the subscription.
	tx, err = other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `DELETE FROM traffic_ledger`)
	usageExec(t, tx, insertNodeUsageRow, "2", "a", "one", "uplink", 8.5, 15)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	checkNodeUsage(t, s, "a", "one", 10, 20, 8.5)
	checkNodeUsage(t, other, "a", "one", 10, 20, 8.5)
	usageExec(t, other.db, `DELETE FROM traffic_ledger`)
	checkNodeUsage(t, s, "a", "one", 10, 20, 0)
}

func usageQueryPlan(t testing.TB, s *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		result = append(result, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func nodeUsageScanOrder(t testing.TB, s *Store) []int64 {
	t.Helper()
	rows, err := s.db.Query(`SELECT rowid FROM traffic_ledger WHERE subscription_id=? AND email=? AND sampled_at>=? AND sampled_at<?`, "a", "one", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNodeTrafficUsageIndexPreservesFloatBitsAndMainPlans(t *testing.T) {
	s, _ := usageStore(t)
	usageExec(t, s.db, `DROP INDEX traffic_ledger_subscription_email`)
	values := []float64{1e16, 0.1, 0.2, 1e-9, 2.75, 1.3, 1, 0.3}
	for i := range 96 {
		// TEXT IDs deliberately disagree with rowid order. Many timestamps
		// coincide, with interleaved emails and both traffic directions.
		email, direction := "one", "uplink"
		if i%3 == 0 {
			email = "two"
		}
		if i%2 == 0 {
			direction = "downlink"
		}
		usageExec(t, s.db, insertNodeUsageRow, fmt.Sprintf("row-%03d", 96-i), "a", email, direction, values[i%len(values)], 10+i%4)
	}
	totalSQL := `SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND sampled_at>=? AND sampled_at<?`
	directionsSQL := `SELECT direction,SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND sampled_at>=? AND sampled_at<? GROUP BY direction`
	args := []any{"a", 0, 100}
	beforePlans := [][]string{usageQueryPlan(t, s, totalSQL, args...), usageQueryPlan(t, s, directionsSQL, args...)}
	beforeOrder := nodeUsageScanOrder(t, s)
	if plan := strings.Join(usageQueryPlan(t, s, nodeUsageSQL, "a", "one", 0, 100), " "); !strings.Contains(plan, "USING INDEX traffic_ledger_subscription (") {
		t.Fatal("unexpected pre-migration node scan", plan)
	}
	ctx := context.Background()
	beforeMain, err := s.queryTrafficUsage(ctx, s.db, "a", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	bounds := [][2]int64{{0, 100}, {10, 11}, {10, 12}, {11, 14}, {13, 14}, {14, 20}, {0, 1}}
	want := make([]float64, len(bounds))
	for i, bound := range bounds {
		want[i], err = s.queryNodeTrafficUsage(ctx, s.db, "a", "one", bound[0], bound[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	usageExec(t, s.db, createNodeUsageIndex)
	if plan := strings.Join(usageQueryPlan(t, s, nodeUsageSQL, "a", "one", 0, 100), " "); !strings.Contains(plan, "USING INDEX traffic_ledger_subscription_email (") || strings.Contains(plan, "COVERING") {
		t.Fatal("node query did not use the non-covering pair/time index", plan)
	}
	if got := nodeUsageScanOrder(t, s); !reflect.DeepEqual(got, beforeOrder) {
		t.Fatal("migration changed tied-timestamp rowid order", beforeOrder, got)
	}
	afterPlans := [][]string{usageQueryPlan(t, s, totalSQL, args...), usageQueryPlan(t, s, directionsSQL, args...)}
	if !reflect.DeepEqual(beforePlans, afterPlans) {
		t.Fatal("node index changed main SUM query plans", beforePlans, afterPlans)
	}
	afterMain, err := s.queryTrafficUsage(ctx, s.db, "a", 0, 100)
	if err != nil || math.Float64bits(beforeMain.Total) != math.Float64bits(afterMain.Total) || math.Float64bits(beforeMain.Up) != math.Float64bits(afterMain.Up) || math.Float64bits(beforeMain.Down) != math.Float64bits(afterMain.Down) {
		t.Fatal("main SUM bits changed", beforeMain, afterMain, err)
	}
	for i, bound := range bounds {
		checkNodeUsage(t, s, "a", "one", bound[0], bound[1], want[i])
	}
}

func TestNodeTrafficUsageMovingBoundariesAndCancellation(t *testing.T) {
	s, _ := usageStore(t)
	for i, at := range []int64{10, 11, 15, 20, 1000000} {
		usageExec(t, s.db, insertNodeUsageRow, fmt.Sprint(i), "a", "one", "uplink", float64(i)+0.1, at)
	}
	// Moving no-reset ends may pass future imports, shrink after a clock
	// correction, or cross a cycle reset. Never reuse a result across a row.
	for _, bound := range [][2]int64{{10, 20}, {10, 21}, {10, 1000000}, {10, 1000001}, {10, 1000002}, {10, 21}, {11, 21}, {20, 21}, {20, 20}, {10, 1}, {0, 2000000}} {
		want, err := s.queryNodeTrafficUsage(context.Background(), s.db, "a", "one", bound[0], bound[1])
		if err != nil {
			t.Fatal(err)
		}
		checkNodeUsage(t, s, "a", "one", bound[0], bound[1], want)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.NodeTrafficUsage(ctx, "a", "one", 0, 2000000); err == nil {
		t.Fatal("canceled request returned cached success")
	}
}

func TestNodeTrafficUsageMigrationReopenAndInstanceIsolation(t *testing.T) {
	s, path := usageStore(t)
	usageExec(t, s.db, `DROP INDEX traffic_ledger_subscription_email`)
	usageExec(t, s.db, insertNodeUsageRow, "old", "a", "one", "uplink", 17.5, 10)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reopened, err := Open(Config{Driver: "sqlite", DSN: path})
		if err != nil {
			t.Fatal(err)
		}
		checkNodeUsage(t, reopened, "a", "one", 0, 100, 17.5)
		plan := strings.Join(usageQueryPlan(t, reopened, nodeUsageSQL, "a", "one", 0, 100), " ")
		if !strings.Contains(plan, "traffic_ledger_subscription_email") {
			t.Fatal("legacy database missing pair index", plan)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
	other, _ := usageStore(t)
	usageExec(t, other.db, insertNodeUsageRow, "old", "a", "one", "uplink", 99, 10)
	checkNodeUsage(t, other, "a", "one", 0, 100, 99)
}

func TestNodeTrafficUsageConcurrentSnapshots(t *testing.T) {
	s, path := usageStore(t)
	writer, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 80 {
				used, err := s.NodeTrafficUsage(context.Background(), "a", "one", 0, 1000)
				if err != nil || int64(used)%3 != 0 {
					t.Errorf("partial node snapshot: %v, %v", used, err)
					return
				}
			}
		})
	}
	for i := range 40 {
		tx, err := writer.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		usageExec(t, tx, insertNodeUsageRow, fmt.Sprintf("u%d", i), "a", "one", "uplink", 1, i)
		usageExec(t, tx, insertNodeUsageRow, fmt.Sprintf("d%d", i), "a", "one", "downlink", 2, i)
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	checkNodeUsage(t, s, "a", "one", 0, 1000, 120)
}

func TestNodeTrafficUsageCacheBound(t *testing.T) {
	s, _ := usageStore(t)
	for i := range nodeTrafficUsageCacheLimit + 7 {
		checkNodeUsage(t, s, "a", fmt.Sprint(i), 0, 100, 0)
	}
	if len(s.nodeUsageCache) > nodeTrafficUsageCacheLimit {
		t.Fatal("unbounded node cache", len(s.nodeUsageCache))
	}
	usageExec(t, s.db, insertNodeUsageRow, "after-eviction", "a", "0", "uplink", 7.5, 10)
	checkNodeUsage(t, s, "a", "0", 0, 100, 7.5)
}

func BenchmarkNodeTrafficUsage310000Rows(b *testing.B) {
	s, _ := usageStore(b)
	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for i := range 310000 {
		usageExec(b, tx, insertNodeUsageRow, fmt.Sprint(i), fmt.Sprint(i%9), fmt.Sprintf("email-%d", (i/9)%20), "uplink", float64(i%1000)*1.3, i/3)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, mode := range []string{"legacy_subscription_scan", "indexed_node_sum", "cached", "changed_revision"} {
		b.Run(mode, func(b *testing.B) {
			checkNodeUsage(b, s, "0", "email-0", 0, 200000, mustNodeUsage(b, s))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "changed_revision" {
					usageExec(b, s.db, `UPDATE traffic_ledger SET weighted_bytes=weighted_bytes+1 WHERE id='0'`)
				}
				var err error
				switch mode {
				case "legacy_subscription_scan":
					var summed sql.NullFloat64
					err = s.db.QueryRowContext(ctx, `SELECT SUM(weighted_bytes) FROM traffic_ledger INDEXED BY traffic_ledger_subscription WHERE subscription_id=? AND email=? AND sampled_at>=? AND sampled_at<?`, "0", "email-0", 0, 200000).Scan(&summed)
				case "indexed_node_sum":
					_, err = s.queryNodeTrafficUsage(ctx, s.db, "0", "email-0", 0, 200000)
				default:
					_, err = s.NodeTrafficUsage(ctx, "0", "email-0", 0, 200000)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func mustNodeUsage(t testing.TB, s *Store) float64 {
	t.Helper()
	used, err := s.queryNodeTrafficUsage(context.Background(), s.db, "0", "email-0", 0, 200000)
	if err != nil {
		t.Fatal(err)
	}
	return used
}
