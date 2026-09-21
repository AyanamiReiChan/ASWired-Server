package httpapi

import (
	"context"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMergedMembershipPreservesInstanceIPRestrictions(t *testing.T) {
	sub := store.Record{Data: map[string]any{"whitelist": []any{"192.0.2.0/24", "2001:db8::1"}}}
	for _, remote := range []string{"192.0.2.8:2345", "[2001:db8::1]:443", "192.0.2.8", "2001:db8::1"} {
		if !membershipIPAllowed(sub, remote) {
			t.Fatal("allowed address rejected", remote)
		}
	}
	for _, remote := range []string{"198.51.100.8:2345", "[2001:db8::2]:443", "malformed"} {
		if membershipIPAllowed(sub, remote) {
			t.Fatal("restricted instance accepted", remote)
		}
	}
}

func membershipFixture(t *testing.T) (*App, store.User, []store.User) {
	a, admin, _, _ := identityFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "plans", ID: "plan", Data: map[string]any{"name": "Plan", "status": "启用", "limit": 12.0, "cycleDays": 30.0, "selfService": true, "price": 24.0}})
	if err != nil {
		t.Fatal(err)
	}
	users := []store.User{}
	for _, id := range []string{"member-a", "member-b"} {
		u := store.User{ID: id, Username: id, Role: "user", PasswordHash: admin.PasswordHash}
		if err = a.DB.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		users = append(users, u)
	}
	return a, admin, users
}
func generatedMembershipCode(t *testing.T, a *App, admin store.User, uses int) string {
	t.Helper()
	result, err := a.membershipCodes(context.Background(), admin, map[string]any{"planId": "plan", "count": 1.0, "days": 30.0, "maxUses": float64(uses)})
	if err != nil {
		t.Fatal(err)
	}
	return result["codes"].([]map[string]any)[0]["code"].(string)
}
func TestMembershipConcurrentLastRedemption(t *testing.T) {
	a, admin, users := membershipFixture(t)
	ctx := context.Background()
	code := generatedMembershipCode(t, a, admin, 1)
	var succeeded atomic.Int32
	var winner atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := a.membershipRedeem(ctx, users[i%2], code)
			if err == nil && result["alreadyRedeemed"] != true {
				succeeded.Add(1)
				winner.Store(int32(i % 2))
			}
		}(i)
	}
	wg.Wait()
	if succeeded.Load() != 1 {
		t.Fatalf("issued %d subscriptions", succeeded.Load())
	}
	subs, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil || len(subs) != 1 {
		t.Fatalf("subscriptions=%d, err=%v", len(subs), err)
	}
	if number(subs[0].Data, "limit") != 12 {
		t.Fatal("code failed to inherit quota")
	}
	codeRec, _ := a.DB.GetRecord(ctx, "_membershipCodes", membershipHash(code))
	if number(codeRec.Data, "used") != 1 {
		t.Fatal("wrong consumption count")
	}
	again, err := a.membershipRedeem(ctx, users[winner.Load()], code)
	if err != nil || again["alreadyRedeemed"] != true {
		t.Fatal("retry did not return original result", err)
	}
	second := generatedMembershipCode(t, a, admin, 1)
	if _, err = a.membershipRedeem(ctx, users[winner.Load()], second); err == nil {
		t.Fatal("duplicate plan accepted")
	}
	untouched, _ := a.DB.GetRecord(ctx, "_membershipCodes", membershipHash(second))
	if number(untouched.Data, "used") != 0 {
		t.Fatal("duplicate plan consumed a code")
	}
}
func TestMembershipRejectsExpiredRevokedAndUnauthorized(t *testing.T) {
	a, admin, users := membershipFixture(t)
	ctx := context.Background()
	code := generatedMembershipCode(t, a, admin, 2)
	rec, _ := a.DB.GetRecord(ctx, "_membershipCodes", membershipHash(code))
	rec.Data["expires"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
	rec, _ = a.DB.SaveRecord(ctx, rec)
	if _, err := a.membershipRedeem(ctx, users[0], code); err == nil {
		t.Fatal("expired code accepted")
	}
	rec.Data["expires"] = ""
	rec.Data["revoked"] = true
	_, _ = a.DB.SaveRecord(ctx, rec)
	if _, err := a.membershipRedeem(ctx, users[0], code); err == nil {
		t.Fatal("revoked code accepted")
	}
	handled, _, err := a.membershipAction(ctx, users[0], actionInput{Action: "membership.code.create", Params: map[string]any{}})
	if !handled || err == nil {
		t.Fatal("ordinary user created code")
	}
}
func TestMembershipRequestRequiresManualConfirmation(t *testing.T) {
	a, admin, users := membershipFixture(t)
	ctx := context.Background()
	req, err := a.membershipRequest(ctx, users[0], "plan", "线下核对")
	if err != nil {
		t.Fatal(err)
	}
	subs, _ := a.DB.ListRecords(ctx, "subscriptions", users[0].ID)
	if len(subs) != 0 {
		t.Fatal("request silently granted a paid plan")
	}
	id := req["requestId"].(string)
	row, _ := a.DB.GetRecord(ctx, "_membershipRequests", id)
	in := actionInput{Action: "membership.request.confirm", TargetID: id, Params: map[string]any{"days": 30.0, "recordVersion": float64(row.Version)}}
	if _, err = a.membershipConfirmRequest(ctx, admin, in); err == nil {
		t.Fatal("approval without confirmation")
	}
	in.Params["confirmed"] = true
	result, err := a.membershipConfirmRequest(ctx, admin, in)
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.membershipConfirmRequest(ctx, admin, in)
	if err != nil || again["alreadyProcessed"] != true {
		t.Fatal("approval retry not idempotent", err)
	}
	sub, _ := a.DB.GetRecord(ctx, "subscriptions", result["subscriptionId"].(string))
	if sub.OwnerID != users[0].ID {
		t.Fatal("wrong owner")
	}
	if _, err = a.membershipDeclare(ctx, users[1], sub.ID, ""); err == nil {
		t.Fatal("cross-owner renewal allowed")
	}
}
func TestMembershipRenewalIsAtomicAndKeepsUsage(t *testing.T) {
	a, admin, users := membershipFixture(t)
	ctx := context.Background()
	sub, err := a.membershipNewSubscription(ctx, users[0], "plan", 30)
	if err != nil {
		t.Fatal(err)
	}
	sub.Data["usedBytes"] = 128.0
	sub, err = a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	original := dateTime(text(sub.Data, "expires"))
	_, err = a.membershipDeclare(ctx, users[0], sub.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	declaration, _ := a.DB.GetRecord(ctx, "_renewalDeclarations", sub.ID)
	in := actionInput{Action: "subscription.renewal.confirm", TargetID: sub.ID, Params: map[string]any{"confirmed": true, "days": 30.0, "recordVersion": float64(declaration.Version)}}
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = a.membershipConfirmRenewal(ctx, admin, in) }()
	}
	wg.Wait()
	after, err := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !dateTime(text(after.Data, "expires")).Equal(original.AddDate(0, 0, 30)) {
		t.Fatal("renewal applied more than once")
	}
	if number(after.Data, "usedBytes") != 128 {
		t.Fatal("renewal discarded usage")
	}
	history, _ := a.DB.ListRecords(ctx, "_renewalHistory", users[0].ID)
	if len(history) != 1 {
		t.Fatal("duplicate renewal history")
	}
	if _, err = a.DB.GetRecord(ctx, "_renewalHistory", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestMembershipTrafficResetMovesWindowWithoutDeletingLedger(t *testing.T) {
	a, admin, users := membershipFixture(t)
	ctx := context.Background()
	sub, err := a.membershipNewSubscription(ctx, users[0], "plan", 30)
	if err != nil {
		t.Fatal(err)
	}
	sub.Data["cycleStart"] = time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	sub, err = a.DB.SaveRecord(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.ensureTrafficSchema(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "before-reset", "server", sub.ID, sub.OwnerID, "test", "uplink", 1024, 1, 1024, time.Now().Add(-time.Minute).UnixMilli(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	before, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil || before != 1024 {
		t.Fatal("fixture accounting failed", before, err)
	}
	in := actionInput{Action: "subscription.traffic.reset", TargetID: sub.ID, Params: map[string]any{"confirmed": true, "recordVersion": float64(sub.Version), "requestId": "reset-request-id-1"}}
	_, err = a.membershipResetTraffic(ctx, admin, in)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	used, _, _, err := a.subscriptionUsage(ctx, after)
	if err != nil || used != 0 {
		t.Fatal("window not reset", used, err)
	}
	again, err := a.membershipResetTraffic(ctx, admin, in)
	if err != nil || again["alreadyProcessed"] != true {
		t.Fatal("reset not idempotent", err)
	}
	var count int
	if err = a.DB.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM traffic_ledger").Scan(&count); err != nil || count != 1 {
		t.Fatal("reset deleted historical ledger", err)
	}
}
