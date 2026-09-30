package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"modernc.org/sqlite"
)

func assertLegacyWindow(t testing.TB, s *Store, subscriptionID string, start, end int64, emails ...string) {
	t.Helper()
	ctx := context.Background()
	want, err := s.queryTrafficUsage(ctx, s.db, subscriptionID, start, end)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := s.SubscriptionUsage(ctx, subscriptionID, start, end)
		if err != nil || !sameUsageBits(got, want) {
			t.Fatalf("%s [%d,%d) usage bits: got %+v want %+v: %v", subscriptionID, start, end, got, want, err)
		}
	}
	for _, email := range emails {
		wantNode, err := s.queryNodeTrafficUsage(ctx, s.db, subscriptionID, email, start, end)
		if err != nil {
			t.Fatal(err)
		}
		checkNodeUsage(t, s, subscriptionID, email, start, end, wantNode)
	}
}

func TestTrafficWindowContinuousMultiNodeAndTiedTimestampBits(t *testing.T) {
	s, _ := usageStore(t)
	random := rand.New(rand.NewSource(82))
	values := []float64{1e16, 0.1, -1e16, 0.2, 1e-9, 2.75, 1.3, 1, 0.3}
	for batch := range 90 {
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		// Multiple nodes report counters in a different order, but all normal
		// lateness fits the replay window. Ties deliberately have reverse IDs.
		for i := range 18 {
			direction := []string{"uplink", "downlink", "other"}[i%3]
			at := int64(100_000 + batch*5000 - random.Intn(4)*5000)
			usageExec(t, tx, insertNodeUsageRow, fmt.Sprintf("%03d-%03d", batch, 18-i), "a", fmt.Sprint(i%3), direction, values[random.Intn(len(values))], at)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		assertLegacyWindow(t, s, "a", 0, 1_000_000, "0", "1", "2")
		if !s.usageCache["a"].incremental {
			t.Fatal("ordinary REAL traffic unexpectedly fell back to SQL")
		}
	}
	if s.usageCache["a"].frontier <= 100_000 {
		t.Fatal("continuous writes never advanced the frozen prefix")
	}
	// Bound changes, including a future import and a backwards wall clock,
	// must not retain bytes outside the exact half-open interval.
	usageExec(t, s.db, insertNodeUsageRow, "future", "a", "0", "downlink", 0.125, 2_000_000)
	for _, bounds := range [][2]int64{{0, 1_000_000}, {0, 2_000_000}, {0, 2_000_001}, {0, 3_000_000}, {0, 100_000}, {100_000, 150_000}, {150_000, 150_000}, {150_000, 140_000}, {0, 3_000_000}} {
		assertLegacyWindow(t, s, "a", bounds[0], bounds[1], "0", "1", "2")
	}
}

func TestTrafficWindowMutationReplaceRowIDAndRollback(t *testing.T) {
	s, path := usageStore(t)
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	for i := range 100 {
		usageExec(t, other.db, insertNodeUsageRow, fmt.Sprint(i), "a", "one", "uplink", float64(i)*1.3, i*5000)
	}
	check := func() {
		for _, sub := range []string{"a", "b", "c"} {
			assertLegacyWindow(t, s, sub, 0, 2_000_000, "one", "two")
		}
	}
	check()
	for _, query := range []string{
		`UPDATE traffic_ledger SET weighted_bytes=0.1,direction='downlink' WHERE id='0'`,
		`UPDATE traffic_ledger SET sampled_at=123456,rowid=9999 WHERE id='2'`,
		`DELETE FROM traffic_ledger WHERE id='3'`,
		`UPDATE traffic_ledger SET subscription_id='b',email='two' WHERE id='4'`,
		// REPLACE's implicit DELETE does not fire delete triggers with the
		// default recursive_triggers=OFF. Its displaced scope must still change.
		`INSERT OR REPLACE INTO traffic_ledger SELECT id,server_id,'b',owner_id,'two',direction,raw_bytes,factor,0.2,900000,gap,gap_reason FROM traffic_ledger WHERE id='5'`,
		`INSERT OR REPLACE INTO traffic_ledger(rowid,id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(9999,'new-rowid','server','c','owner','two','downlink',1,1,2.3,950000,0,'')`,
		`UPDATE OR REPLACE traffic_ledger SET id='6',subscription_id='c',email='two',sampled_at=1000000 WHERE id='7'`,
		`UPDATE OR REPLACE traffic_ledger SET rowid=9999,subscription_id='b',email='one',sampled_at=1050000 WHERE id='8'`,
		// Late historical data predates the frozen prefix.
		`INSERT INTO traffic_ledger SELECT 'late',server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,0.7,1,gap,gap_reason FROM traffic_ledger WHERE id='9'`,
	} {
		usageExec(t, other.db, query)
		check()
	}
	tx, err := other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `DELETE FROM traffic_ledger`)
	usageExec(t, tx, insertNodeUsageRow, "rollback", "a", "one", "downlink", 999, 1_100_000)
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	check()
	tx, err = other.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	usageExec(t, tx, `DELETE FROM traffic_ledger`)
	usageExec(t, tx, insertNodeUsageRow, "0", "a", "one", "downlink", 0.1, 0)
	usageExec(t, tx, insertNodeUsageRow, "1", "a", "one", "downlink", 0.2, 1_200_000)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestTrafficWindowLegacyMigrationAndFirstOutOfOrderInsert(t *testing.T) {
	s, path := usageStore(t)
	for _, name := range []string{"traffic_window_INSERT", "traffic_window_DELETE", "traffic_window_UPDATE", "traffic_window_conflict_INSERT", "traffic_window_conflict_UPDATE"} {
		usageExec(t, s.db, `DROP TRIGGER `+name)
	}
	usageExec(t, s.db, `DROP TABLE traffic_usage_windows`)
	usageExec(t, s.db, insertNodeUsageRow, "old", "a", "one", "uplink", 1e16, 200_000)
	usageExec(t, s.db, insertNodeUsageRow, "old-two", "a", "one", "uplink", 0.1, 210_000)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertLegacyWindow(t, reopened, "a", 0, 1_000_000, "one")
	usageExec(t, reopened.db, insertNodeUsageRow, "late-first", "a", "one", "uplink", -1e16, 1)
	assertLegacyWindow(t, reopened, "a", 0, 1_000_000, "one")
	usageExec(t, reopened.db, insertNodeUsageRow, "late-second", "a", "one", "uplink", 0.3, 2)
	assertLegacyWindow(t, reopened, "a", 0, 1_000_000, "one")
}

func TestTrafficWindowDelayedReaderAndExactReplayBoundary(t *testing.T) {
	s, _ := usageStore(t)
	usageExec(t, s.db, insertNodeUsageRow, "prefix", "a", "one", "uplink", 1e16, 0)
	usageExec(t, s.db, insertNodeUsageRow, "warm-tail", "a", "one", "uplink", 0.1, 100_000)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	// Several writes can advance the database high-water mark while a reader
	// still holds an older prefix. A late row must be judged against the DB
	// watermark, and replay must still begin at the reader's older frontier.
	for i, at := range []int64{150_000, 200_000, 250_000, 190_000} {
		usageExec(t, s.db, insertNodeUsageRow, fmt.Sprintf("unread-%d", i), "a", "one", "uplink", []float64{0.2, -1e16, 0.3, 1.3}[i], at)
	}
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	mutation := s.usageCache["a"].mutation
	usageExec(t, s.db, insertNodeUsageRow, "exact-boundary", "a", "one", "uplink", 2.75, 190_000)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	if s.usageCache["a"].mutation != mutation {
		t.Fatal("a row exactly at the replay frontier invalidated the frozen prefix")
	}
	usageExec(t, s.db, insertNodeUsageRow, "outside-boundary", "a", "one", "uplink", 1e-9, 189_999)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	if s.usageCache["a"].mutation == mutation {
		t.Fatal("a row one millisecond before the replay frontier left the prefix valid")
	}
}

var trafficWindowProbeOnce sync.Once
var trafficWindowProbeReads atomic.Int64

func TestTrafficWindowReadsOnlyTailAndKeepsUnchangedNodeWarm(t *testing.T) {
	trafficWindowProbeOnce.Do(func() {
		if err := sqlite.RegisterScalarFunction("test_traffic_window_read", 1, func(_ *sqlite.FunctionContext, values []driver.Value) (driver.Value, error) {
			trafficWindowProbeReads.Add(1)
			return values[0], nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	s, _ := usageStore(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5000 {
		usageExec(t, tx, insertNodeUsageRow, fmt.Sprint(i), "a", fmt.Sprint(i%2), "downlink", 1.3, i*1000)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Observe actual row reads instead of relying on timings or a production
	// test hook. Preserve rowid explicitly so tied-timestamp ordering is real.
	usageExec(t, s.db, `ALTER TABLE traffic_ledger RENAME TO traffic_window_probe_ledger`)
	usageExec(t, s.db, `CREATE VIEW traffic_ledger AS SELECT rowid,id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,test_traffic_window_read(weighted_bytes) AS weighted_bytes,sampled_at,gap,gap_reason FROM traffic_window_probe_ledger`)
	assertLegacyWindow(t, s, "a", 0, 10_000_000, "0", "1")
	trafficWindowProbeReads.Store(0)
	usageExec(t, s.db, strings.Replace(insertNodeUsageRow, "traffic_ledger", "traffic_window_probe_ledger", 1), "next", "a", "0", "downlink", 1.3, 5_000_000)
	if _, err := s.NodeTrafficUsage(context.Background(), "a", "1", 0, 10_000_000); err != nil {
		t.Fatal(err)
	}
	if reads := trafficWindowProbeReads.Load(); reads != 0 {
		t.Fatalf("one node invalidated another node's warm sum: %d reads", reads)
	}
	if _, err := s.SubscriptionUsage(context.Background(), "a", 0, 10_000_000); err != nil {
		t.Fatal(err)
	}
	if reads := trafficWindowProbeReads.Swap(0); reads == 0 || reads > 65 {
		t.Fatalf("append read %d rows; expected only the one-minute tail, not 5001 history rows", reads)
	}
	// A node that arrives 30 seconds late still only replays the bounded tail.
	usageExec(t, s.db, strings.Replace(insertNodeUsageRow, "traffic_ledger", "traffic_window_probe_ledger", 1), "delayed", "a", "1", "downlink", 0.1, 4_970_000)
	if _, err := s.SubscriptionUsage(context.Background(), "a", 0, 10_000_000); err != nil {
		t.Fatal(err)
	}
	if reads := trafficWindowProbeReads.Load(); reads == 0 || reads > 65 {
		t.Fatalf("slightly late node read %d rows instead of only the tail", reads)
	}
	assertLegacyWindow(t, s, "a", 0, 10_000_000, "0", "1")
}

func TestTrafficWindowUnexpectedSQLiteTypesAndFiniteOverflow(t *testing.T) {
	s, _ := usageStore(t)
	usageExec(t, s.db, insertNodeUsageRow, "base", "a", "one", "uplink", 1.3, 0)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	// SQLite accepts nonnumeric text in a REAL-affinity column and SUM treats
	// it as zero. Do not make a malformed import block all quota evaluation.
	usageExec(t, s.db, insertNodeUsageRow, "text", "a", "one", "uplink", "malformed", 100_000)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	if s.usageCache["a"].incremental {
		t.Fatal("unexpected SQLite type retained incremental state")
	}
	usageExec(t, s.db, `DELETE FROM traffic_ledger WHERE id='text'`)
	usageExec(t, s.db, insertNodeUsageRow, "large", "a", "one", "uplink", math.MaxFloat64, 200_000)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
	usageExec(t, s.db, insertNodeUsageRow, "overflow", "a", "one", "uplink", math.MaxFloat64, 210_000)
	assertLegacyWindow(t, s, "a", 0, 1_000_000, "one")
}

// Each timed operation commits writes from multiple nodes and reads total,
// directions, and node usage. Static warm-cache benchmarks miss this workload.
func BenchmarkTrafficWindowContinuousWrites(b *testing.B) {
	for _, history := range []int{82_000, 1_240_000} {
		b.Run(fmt.Sprint(history), func(b *testing.B) {
			s, _ := usageStore(b)
			tx, err := s.db.Begin()
			if err != nil {
				b.Fatal(err)
			}
			for i := range history {
				usageExec(b, tx, insertNodeUsageRow, fmt.Sprint(i), fmt.Sprint(i%9), fmt.Sprint((i/9)%6), []string{"uplink", "downlink"}[i%2], float64(i%1000)*1.3, i*1000)
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}
			ctx := context.Background()
			for _, mode := range []string{"legacy", "ordered", "multi_node_30s_late", "historical_120s_late"} {
				b.Run(mode, func(b *testing.B) {
					for sub := range 9 {
						assertLegacyWindow(b, s, fmt.Sprint(sub), 0, math.MaxInt64, "0", "1", "2", "3", "4", "5")
					}
					var lastAt int64
					if err := s.db.QueryRow(`SELECT MAX(sampled_at) FROM traffic_ledger`).Scan(&lastAt); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						tx, err := s.db.Begin()
						if err != nil {
							b.Fatal(err)
						}
						for sub := range 9 {
							for node := range 6 {
								at := lastAt + int64(i+1)*5000
								if node%2 == 1 && mode == "multi_node_30s_late" {
									at -= 30_000
								}
								if node%2 == 1 && mode == "historical_120s_late" {
									at -= 120_000
								}
								usageExec(b, tx, insertNodeUsageRow, fmt.Sprintf("%s-%d-%d-%d-%d", mode, lastAt, i, sub, node), fmt.Sprint(sub), fmt.Sprint(node), "downlink", 1.3, at)
							}
						}
						if err := tx.Commit(); err != nil {
							b.Fatal(err)
						}
						for sub := range 9 {
							if mode == "legacy" {
								_, err = s.queryTrafficUsage(ctx, s.db, fmt.Sprint(sub), 0, math.MaxInt64)
							} else {
								_, err = s.SubscriptionUsage(ctx, fmt.Sprint(sub), 0, math.MaxInt64)
							}
							if err != nil {
								b.Fatal(err)
							}
							for node := range 6 {
								if mode == "legacy" {
									_, err = s.queryNodeTrafficUsage(ctx, s.db, fmt.Sprint(sub), fmt.Sprint(node), 0, math.MaxInt64)
								} else {
									_, err = s.NodeTrafficUsage(ctx, fmt.Sprint(sub), fmt.Sprint(node), 0, math.MaxInt64)
								}
								if err != nil {
									b.Fatal(err)
								}
							}
						}
					}
				})
			}
		})
	}
}
