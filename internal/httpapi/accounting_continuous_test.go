package httpapi

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// Synthetic sustained reporting: fourteen subscriptions, ten servers, seven
// active subscribers, default behavior rules, and two node quotas on one plan.
// No production records, credentials, or network connections are used.
func continuousAccountingFixture(t testing.TB, rows int) (*App, []store.Record, int64) {
	t.Helper()
	a, original := subscriptionFixture(t)
	ctx := context.Background()
	save := func(row store.Record) store.Record {
		t.Helper()
		result, err := a.DB.SaveRecord(ctx, row)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if err := a.DB.DeleteRecord(ctx, "nodes", "ss-node"); err != nil {
		t.Fatal(err)
	}
	for server := range 10 {
		id := fmt.Sprintf("report-server-%d", server)
		save(store.Record{Collection: "servers", ID: id, Data: map[string]any{"name": id, "address": "127.0.0.1", "connection": "WebSocket", "multiplier": 1.3}})
		inbound := realityInboundFixtureData()
		inbound["serverId"], inbound["tag"], inbound["name"] = id, id, id
		save(store.Record{Collection: "inbounds", ID: id, Data: inbound})
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-24 * time.Hour).UnixMilli()
	subs := make([]store.Record, 14)
	for user := range subs {
		id := fmt.Sprintf("report-user-%d", user)
		if err := a.DB.CreateUser(ctx, store.User{ID: id, Username: id, Role: "user", PasswordHash: "synthetic-test-hash"}); err != nil {
			t.Fatal(err)
		}
		planID := fmt.Sprintf("report-plan-%d", user)
		plan := map[string]any{"name": planID, "status": "已发布", "limit": 1000000, "directionFactor": 1, "reset": "none"}
		if user == 0 {
			plan["nodeTraffic"] = map[string]any{"inbound-report-server-0": map[string]any{"limit": 1000000}, "inbound-report-server-1": map[string]any{"limit": 1000000}}
		}
		save(store.Record{Collection: "plans", ID: planID, Data: plan})
		data := clone(original.Data)
		data["planId"], data["memberId"], data["credentialEmail"] = planID, id, id
		data["cycleStart"], data["cycleEnd"] = time.UnixMilli(base-int64(rows)-10000).UTC().Format(time.RFC3339Nano), ""
		data["nodeIds"] = []string{}
		subs[user] = save(store.Record{Collection: "subscriptions", ID: fmt.Sprintf("report-sub-%d", user), OwnerID: id, Data: data})
	}
	if err := a.DB.DeleteRecord(ctx, "subscriptions", original.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := a.DB.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,1000,1.3,1300,?,0,'')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		sub := subs[(i/2)%len(subs)]
		serverID := fmt.Sprintf("report-server-%d", (i/(2*len(subs)))%10)
		direction := "uplink"
		if i%2 != 0 {
			direction = "downlink"
		}
		if _, err := statement.Exec(fmt.Sprint(i), serverID, sub.ID, sub.OwnerID, text(sub.Data, "credentialEmail")+"."+serverID, direction, base-int64(rows)+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	statement.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return a, subs, base
}

func continuousAccountingRound(a *App, subs []store.Record, base int64, round int) {
	for server := range 10 {
		serverID := fmt.Sprintf("report-server-%d", server)
		counters := map[string]any{}
		for _, sub := range subs[:7] {
			prefix := "user>>>" + text(sub.Data, "credentialEmail") + "." + serverID + ">>>traffic>>>"
			counters[prefix+"uplink"] = int64(round+1) * 50000
			counters[prefix+"downlink"] = int64(round+1) * 250000
		}
		a.accountStats(context.Background(), serverID, map[string]any{"timestamp": base + int64(round)*5000, "generation": "continuous-fixture", "counters": counters})
	}
}

func verifyContinuousAccounting(t testing.TB, a *App, subs []store.Record, rows, rounds int) {
	t.Helper()
	ctx := context.Background()
	var count int
	if err := a.DB.DB().QueryRow(`SELECT COUNT(*) FROM traffic_ledger`).Scan(&count); err != nil || count != rows+rounds*140 {
		t.Fatalf("ledger count = %d, want %d: %v", count, rows+rounds*140, err)
	}
	for _, sub := range subs {
		current, err := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
		if err != nil {
			t.Fatal(err)
		}
		total, up, down, err := a.subscriptionUsage(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		var want, wantUp, wantDown float64
		if err := a.DB.DB().QueryRow(`SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=?`, sub.ID).Scan(&want); err != nil {
			t.Fatal(err)
		}
		for direction, result := range map[string]*float64{"uplink": &wantUp, "downlink": &wantDown} {
			if err := a.DB.DB().QueryRow(`SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND direction=?`, sub.ID, direction).Scan(result); err != nil {
				t.Fatal(err)
			}
		}
		if math.Float64bits(total) != math.Float64bits(want) || math.Float64bits(up) != math.Float64bits(wantUp) || math.Float64bits(down) != math.Float64bits(wantDown) {
			t.Fatalf("%s usage differs: %v/%v/%v versus %v/%v/%v", sub.ID, total, up, down, want, wantUp, wantDown)
		}
	}
	states, err := a.DB.ListRecords(ctx, "_limitState", "")
	if err != nil || len(states) != 70 {
		t.Fatalf("default behavior was not evaluated: states=%d, error=%v", len(states), err)
	}
	for _, record := range states {
		state := readBehaviorState(record.Data)
		if len(state.Rules) != 2 {
			t.Fatalf("default rules missing from %s", record.ID)
		}
		for _, rule := range state.Rules {
			if rule.Until != 0 {
				t.Fatalf("low-rate fixture unexpectedly penalized %s", record.ID)
			}
		}
	}
}

func TestAccountStatsContinuousLedgerMatchesSQL(t *testing.T) {
	a, subs, base := continuousAccountingFixture(t, 560)
	for round := range 3 {
		continuousAccountingRound(a, subs, base, round)
	}
	verifyContinuousAccounting(t, a, subs, 560, 3)
}

// Run with -benchtime=3x or 5x; one operation is ten real accountStats calls
// followed by maintenance, with new rows on every round, not a static cache hit.
func BenchmarkAccountStatsContinuous(b *testing.B) {
	for _, rows := range []int{1240000, 2480000} {
		b.Run(fmt.Sprint(rows), func(b *testing.B) {
			a, subs, base := continuousAccountingFixture(b, rows)
			continuousAccountingRound(a, subs, base, 0)
			a.expireSubscriptions(context.Background())
			b.ReportAllocs()
			b.ResetTimer()
			for round := 1; round <= b.N; round++ {
				continuousAccountingRound(a, subs, base, round)
				a.expireSubscriptions(context.Background())
			}
			b.StopTimer()
			verifyContinuousAccounting(b, a, subs, rows, b.N+1)
		})
	}
}
