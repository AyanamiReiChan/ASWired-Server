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
