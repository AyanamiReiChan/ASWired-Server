package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// Synthetic production-sized ledger; no deployment data is used. This benchmark
// also runs unchanged on v1.0.2 for a whole-maintenance comparison.
func BenchmarkExpireSubscriptions82203Rows(b *testing.B) {
	a, sub := subscriptionFixture(b)
	ctx := context.Background()
	ids := []string{sub.ID}
	for i := 1; i < 9; i++ {
		plan, err := a.DB.GetRecord(ctx, "plans", "plan")
		if err != nil {
			b.Fatal(err)
		}
		plan.ID, plan.Version = fmt.Sprintf("plan%d", i), 0
		if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
			b.Fatal(err)
		}
		row := store.Record{Collection: "subscriptions", ID: fmt.Sprintf("sub%d", i), OwnerID: sub.OwnerID, Data: clone(sub.Data)}
		row.Data["planId"] = plan.ID
		if _, err := a.DB.SaveRecord(ctx, row); err != nil {
			b.Fatal(err)
		}
		ids = append(ids, row.ID)
	}
	tx, err := a.DB.DB().Begin()
	if err != nil {
		b.Fatal(err)
	}
	at := time.Now().UnixMilli()
	for i := range 82203 {
		direction := "uplink"
		if i%2 == 0 {
			direction = "downlink"
		}
		_, err := tx.Exec(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,'member','synthetic',?,1000,1.3,1300,?,0,'')`, fmt.Sprint(i), ids[i%9], direction, at+int64(i))
		if err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.expireSubscriptions(ctx)
	}
}

// This fixture includes the previously omitted behavior-state fanout: 44
// server/user states, one user with nine subscriptions, two limited inbounds,
// and 315,000 interleaved ledger samples. No deployment data is used.
func BenchmarkExpireSubscriptionsBehavior315000Rows(b *testing.B) {
	a, original := subscriptionFixture(b)
	ctx := context.Background()
	for _, id := range []string{"limited-a", "limited-b"} {
		data := realityInboundFixtureData()
		data["name"], data["tag"] = id, id
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: id, Data: data}); err != nil {
			b.Fatal(err)
		}
	}
	if err := a.refreshInboundNodes(ctx); err != nil {
		b.Fatal(err)
	}
	base := time.Now().Add(-24 * time.Hour)
	ids := make([]string, 9)
	emails := make([]string, 9)
	for i := range 9 {
		plan, err := a.DB.GetRecord(ctx, "plans", "plan")
		if err != nil {
			b.Fatal(err)
		}
		if i > 0 {
			plan.ID, plan.Version = fmt.Sprintf("behavior-plan-%d", i), 0
		}
		plan.Data["nodeTraffic"] = map[string]any{"inbound-limited-a": map[string]any{"limit": 1000}, "inbound-limited-b": map[string]any{"limit": 1000}}
		if _, err := a.DB.SaveRecord(ctx, plan); err != nil {
			b.Fatal(err)
		}
		sub := original
		sub.Data = clone(original.Data)
		if i > 0 {
			sub.ID, sub.Version = fmt.Sprintf("behavior-sub-%d", i), 0
		}
		sub.Data["planId"] = plan.ID
		sub.Data["credentialEmail"] = fmt.Sprintf("synthetic-%d", i)
		sub.Data["cycleStart"] = base.Add(-time.Hour).Format(time.RFC3339Nano)
		if _, err := a.DB.SaveRecord(ctx, sub); err != nil {
			b.Fatal(err)
		}
		ids[i], emails[i] = sub.ID, text(sub.Data, "credentialEmail")
	}
	// Four servers for eleven users. Ten users have retained state but no
	// subscriptions; the member's nine subscriptions span both limited nodes.
	for user := range 11 {
		owner := original.OwnerID
		if user > 0 {
			owner = fmt.Sprintf("previous-member-%d", user)
		}
		for server := range 4 {
			serverID := "server"
			if server > 0 {
				serverID = fmt.Sprintf("previous-server-%d", server)
			}
			state := behaviorState{At: base.UnixMilli(), Generation: "fixture", Counters: map[string]int64{}, Rules: map[string]behaviorProgress{}}
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_limitState", ID: serverID + "/" + owner, OwnerID: owner, Data: stateData(state)}); err != nil {
				b.Fatal(err)
			}
		}
	}
	tx, err := a.DB.DB().BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,'member',?,?,1000,1.3,1300,?,0,'')`)
	if err != nil {
		b.Fatal(err)
	}
	for i := range 315000 {
		email, direction := emails[i%9]+".limited-a", "uplink"
		if i%2 == 0 {
			email, direction = emails[i%9]+".limited-b", "downlink"
		}
		if _, err := statement.Exec(fmt.Sprint(i), ids[i%9], email, direction, base.UnixMilli()+int64(i)); err != nil {
			b.Fatal(err)
		}
	}
	statement.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.expireSubscriptions(ctx)
	}
}
