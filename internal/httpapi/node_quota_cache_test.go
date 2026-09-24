package httpapi

import (
	"context"
	"testing"
	"time"
)

func TestNodeQuotaCacheUsesCurrentLimitCredentialAndCycle(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	at := time.Now().Add(time.Second).UnixMilli()
	email := text(sub.Data, "credentialEmail") + ".metered"
	entry := map[string]any{"limit": 1000 / gib}
	plan := map[string]any{"nodeTraffic": map[string]any{"node": entry}}
	insert := func(id string, bytes int64, sampledAt int64) {
		t.Helper()
		_, err := a.DB.DB().ExecContext(ctx, `INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,?,?,'downlink',?,1,?,?,0,'')`, id, sub.ID, sub.OwnerID, email, bytes, bytes, sampledAt)
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(want bool) {
		t.Helper()
		got, err := a.planNodeQuotaExceeded(ctx, sub, plan, "node", "metered")
		if err != nil || got != want {
			t.Fatalf("node quota: got %v, want %v: %v", got, want, err)
		}
	}
	insert("node-quota-first", 800, at)
	check(false)
	check(false) // Warm usage must not cache the quota decision.
	entry["limit"] = 800 / gib
	check(true)
	entry["limit"] = 1200 / gib
	check(false)
	insert("node-quota-next", 400, at+1)
	check(true)
	original := sub.Data["credentialEmail"]
	sub.Data["credentialEmail"] = "rotated-credential"
	check(false)
	sub.Data["credentialEmail"] = original
	check(true)
	sub.Data["cycleStart"] = time.UnixMilli(at + 2).UTC().Format(time.RFC3339Nano)
	check(false)
}
