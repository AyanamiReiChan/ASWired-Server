package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func poolSecondSubscription(t *testing.T, a *App, first store.Record) store.Record {
	t.Helper()
	ctx := context.Background()
	if err := a.DB.CreateUser(ctx, store.User{ID: "pool-member", Username: "pool-member", Role: "user", PasswordHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"name": "Second member", "memberId": "pool-member", "planId": text(first.Data, "planId"), "limit": 0}
	owner, err := a.prepareSubscription(httptest.NewRequest("POST", "/", nil), "pool-second", row, false)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "pool-second", OwnerID: owner, Data: row})
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func poolLedger(t *testing.T, a *App, sub store.Record, id string, at time.Time, value float64) {
	t.Helper()
	_, err := a.DB.DB().ExecContext(context.Background(), a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,?,?,'downlink',1,1,?,?,0,'')`), id, sub.ID, sub.OwnerID, text(sub.Data, "credentialEmail"), value, at.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
}

func poolSave(t *testing.T, a *App, rec store.Record) store.Record {
	t.Helper()
	var saved store.Record
	var err error
	if rec.Collection == "plans" {
		saved, err = a.savePlanWithPool(context.Background(), rec)
	} else {
		saved, err = a.DB.SaveRecord(context.Background(), rec)
	}
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestTrafficPoolConvertsExistingPeriodsAndEnforcesAllMembers(t *testing.T) {
	a, first := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	second := poolSecondSubscription(t, a, first)
	now := time.Now().UTC().Truncate(time.Millisecond)
	first.Data["cycleStart"] = cycleStamp(now.Add(-10 * time.Hour))
	second.Data["cycleStart"] = cycleStamp(now.Add(-5 * time.Hour))
	first, second = poolSave(t, a, first), poolSave(t, a, second)
	poolLedger(t, a, first, "old-first", now.Add(-11*time.Hour), 900)
	poolLedger(t, a, first, "current-first", now.Add(-8*time.Hour), 30)
	poolLedger(t, a, second, "old-second", now.Add(-6*time.Hour), 900)
	poolLedger(t, a, second, "current-second", now.Add(-time.Hour), 40)
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"], plan.Data["limit"] = "shared", 100/gib
	plan = poolSave(t, a, plan)
	usage, err := a.sharedPoolUsage(ctx, plan)
	if err != nil || usage.Total != 70 || usage.MemberCount != 2 {
		t.Fatalf("initial pool %+v %v", usage, err)
	}
	if used, _, _, err := a.subscriptionUsage(ctx, first); err != nil || used != 30 {
		t.Fatalf("personal usage changed %v %v", used, err)
	}
	poolLedger(t, a, first, "exhaust", now, 30)
	for _, sub := range []store.Record{first, second} {
		if err := a.subscriptionActive(ctx, sub); err == nil || !strings.Contains(err.Error(), "共享池") {
			t.Fatalf("member %s bypassed pool: %v", sub.ID, err)
		}
		if over, speed, err := a.quotaOutcome(ctx, sub); !over || speed != 0 || err != nil {
			t.Fatalf("quota %s %v %v %v", sub.ID, over, speed, err)
		}
	}
	// A stale unlimited personal override cannot bypass the plan's shared stop.
	second.Data["quotaMode"], second.Data["quotaSpeedMbps"] = "throttle", 100
	if err := a.subscriptionActive(ctx, second); err == nil {
		t.Fatal("personal quota override bypassed shared stop")
	}
	plan.Data["quotaMode"], plan.Data["quotaSpeedMbps"] = "throttle", 2
	plan = poolSave(t, a, plan)
	for _, sub := range []store.Record{first, second} {
		if over, speed, err := a.quotaOutcome(ctx, sub); !over || speed != 2 || err != nil {
			t.Fatalf("shared throttle not applied: %v %v %v", over, speed, err)
		}
	}
	plan.Data["limit"] = 101 / gib
	plan = poolSave(t, a, plan)
	if over, _, err := a.quotaOutcome(ctx, second); over || err != nil {
		t.Fatal("pool expansion did not release", err)
	}
	plan.Data["limit"] = 0
	plan = poolSave(t, a, plan)
	row := map[string]any{}
	if err := a.projectTrafficPool(ctx, "plans", plan, row); err != nil || row["poolRemainingBytes"] != nil {
		t.Fatal("unlimited pool displayed exhausted", row, err)
	}
}

func TestTrafficPoolDeletionModeEditsAndPersonalResetCannotRefund(t *testing.T) {
	a, first := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	second := poolSecondSubscription(t, a, first)
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"] = "shared"
	plan = poolSave(t, a, plan)
	poolLedger(t, a, first, "first", time.Now(), 21)
	poolLedger(t, a, second, "second", time.Now(), 34)
	first, _ = a.DB.GetRecord(ctx, "subscriptions", first.ID)
	_, err := a.membershipResetTraffic(ctx, store.User{ID: "admin", Role: "admin"}, actionInput{TargetID: first.ID, Params: map[string]any{"confirmed": true, "requestId": "pool-should-not-reset", "recordVersion": float64(first.Version)}})
	if err == nil {
		t.Fatal("single-member reset accepted for shared pool")
	}
	if err := a.DB.DeleteRecord(ctx, "subscriptions", first.ID); err != nil {
		t.Fatal(err)
	}
	usage, err := a.sharedPoolUsage(ctx, plan)
	if err != nil || usage.Total != 55 || usage.MemberCount != 1 {
		t.Fatalf("deletion refunded consumed traffic: %+v %v", usage, err)
	}
	for _, mode := range []string{"shared", "individual", "shared"} {
		plan.Data["trafficMode"] = mode
		plan = poolSave(t, a, plan)
	}
	second, _ = a.DB.GetRecord(ctx, "subscriptions", second.ID)
	second.Data["cycleStart"], second.Data["status"] = cycleStamp(time.Now().Add(time.Hour)), "暂停"
	second = poolSave(t, a, second)
	plan.Data["reset"], plan.Data["cycleDays"] = "none", 7
	plan = poolSave(t, a, plan)
	usage, err = a.sharedPoolUsage(ctx, plan)
	if err != nil || usage.Total != 55 || usage.CycleEnd != "" {
		t.Fatalf("policy/mode/personal edits refunded traffic: %+v %v", usage, err)
	}
	// Pool metadata is not owned by a member and survives account deletion.
	pool, _ := a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
	if pool.OwnerID != "" {
		t.Fatal("pool metadata tied to member lifecycle")
	}
	if err := a.DB.DeleteMember(ctx, second.OwnerID); err != nil {
		t.Fatal(err)
	}
	usage, err = a.sharedPoolUsage(ctx, plan)
	if err != nil || usage.Total != 55 || usage.MemberCount != 0 {
		t.Fatalf("account deletion refunded consumed traffic: %+v %v", usage, err)
	}
}

func TestTrafficPoolMaintenanceReconcilesEveryMemberAndRestores(t *testing.T) {
	a, first, key, _ := limitFixture(t, nil)
	defer a.Close()
	ctx := context.Background()
	second := poolSecondSubscription(t, a, first)
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"], plan.Data["limit"] = "shared", 100/gib
	plan = poolSave(t, a, plan)
	server, _ := a.DB.GetRecord(ctx, "servers", "server")
	server.Data["multiplier"] = 1
	poolSave(t, a, server)
	actor := store.User{ID: "admin", Role: "admin"}
	a.reconcileUsers(ctx, actor)
	assertUsers := func(want int) {
		t.Helper()
		state, err := a.DB.GetRecord(ctx, "_userSync", "server/native")
		if err != nil {
			t.Fatal(err)
		}
		task, err := a.DB.GetTask(ctx, text(state.Data, "taskId"))
		if err != nil {
			t.Fatal(err)
		}
		var command agentwire.Command
		if err := json.Unmarshal(task.Input, &command); err != nil {
			t.Fatal(err)
		}
		users, _ := command.Params["users"].([]any)
		if len(users) != want {
			t.Fatalf("queued inbound users=%d want=%d: %s", len(users), want, task.Input)
		}
	}
	assertUsers(2)
	a.accountStats(ctx, "server", map[string]any{"timestamp": time.Now().UnixMilli(), "generation": "pool-test", "counters": map[string]any{key: int64(100)}})
	a.expireSubscriptions(ctx)
	assertUsers(0)
	for _, sub := range []store.Record{first, second} {
		state, err := a.DB.GetRecord(ctx, "_quotaState", sub.ID)
		if err != nil || !boolean(state.Data, "overQuota") {
			t.Fatal("non-contributing member escaped quota state", sub.ID, err)
		}
		events, err := a.DB.ListRecords(ctx, "_limitEvents", sub.OwnerID)
		if err != nil || len(events) != 1 || text(events[0].Data, "type") != "quota_triggered" {
			t.Fatal("shared quota trigger missing", sub.ID, events, err)
		}
	}
	plan, _ = a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["limit"] = 101 / gib
	poolSave(t, a, plan)
	a.expireSubscriptions(ctx)
	assertUsers(2)
	for _, sub := range []store.Record{first, second} {
		state, _ := a.DB.GetRecord(ctx, "_quotaState", sub.ID)
		if boolean(state.Data, "overQuota") {
			t.Fatal("pool expansion did not restore every member")
		}
	}
}

func TestTrafficPoolPublicSubscriptionHeadersUseAggregateAndFailClosed(t *testing.T) {
	a, first := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	second := poolSecondSubscription(t, a, first)
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"], plan.Data["limit"] = "shared", 100/gib
	plan = poolSave(t, a, plan)
	poolLedger(t, a, first, "first", time.Now(), 12)
	poolLedger(t, a, second, "second", time.Now(), 18)
	h := a.Handler()
	admin, _ := a.DB.UserByID(ctx, "admin")
	adminToken, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	member, _ := a.DB.UserByID(ctx, first.OwnerID)
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	input := generatorInput{Name: "Pool generated", NodeIDs: []string{"ss-node"}, SubscriptionID: first.ID, Format: "clash", Mode: "custom", ExpiresInDays: 7, CreateLink: true}
	generated := controllerRequest(t, h, "POST", "/api/subscription-generator", adminToken, input)
	requireStatus(t, generated, 200)
	temporary := temporaryLink(t, h, memberToken, "ss-node", 5)
	links := []string{"/api/clash/subscribe?format=clash&token=" + url.QueryEscape(text(first.Data, "token")), text(responseMap(t, generated), "url"), text(temporary, "url") + "&format=clash"}
	for _, link := range links {
		result := controllerRequest(t, h, "GET", link, "", nil)
		requireStatus(t, result, 200)
		if header := result.Header().Get("Subscription-Userinfo"); !strings.Contains(header, "download=30;") || !strings.Contains(header, "total=100") {
			t.Fatal("public link reported personal quota", link, header)
		}
	}
	pool, _ := a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
	pool.Data["members"] = "damaged"
	poolSave(t, a, pool)
	if err := a.subscriptionActive(ctx, second); err == nil {
		t.Fatal("damaged pool permitted traffic")
	}
	for _, link := range links {
		result := controllerRequest(t, h, "GET", link, "", nil)
		if result.Code == 200 {
			t.Fatal("failed pool lookup served a subscription", link)
		}
	}
}

func TestTrafficPoolUnifiedResetRetiresDeletedContributionsAndJoins(t *testing.T) {
	a, first := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"] = "shared"
	plan = poolSave(t, a, plan)
	second := poolSecondSubscription(t, a, first)
	pool, _ := a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
	members := pool.Data["members"].(map[string]any)
	if len(members) != 2 {
		t.Fatal("new subscription was not atomically registered")
	}
	boundary := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Second)
	poolLedger(t, a, first, "retired", boundary.Add(-time.Millisecond), 31)
	poolLedger(t, a, second, "before", boundary.Add(-time.Millisecond), 13)
	poolLedger(t, a, second, "exact", boundary, 7)
	if err := a.DB.DeleteRecord(ctx, "subscriptions", first.ID); err != nil {
		t.Fatal(err)
	}
	pool.Data["cycleEnd"] = cycleStamp(boundary)
	poolSave(t, a, pool)
	usage, err := a.sharedPoolUsage(ctx, plan)
	if err != nil || usage.Total != 7 || usage.CycleStart != cycleStamp(boundary) {
		t.Fatalf("reset boundary %+v %v", usage, err)
	}
	pool, _ = a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
	members = pool.Data["members"].(map[string]any)
	if len(members) != 1 || members[first.ID] != nil {
		t.Fatal("retired contribution windows accumulated beyond reset")
	}
}

func TestTrafficPoolSnapshotAndProjectionPrivacy(t *testing.T) {
	a, first := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	second := poolSecondSubscription(t, a, first)
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	plan.Data["trafficMode"], plan.Data["limit"] = "shared", 100/gib
	plan = poolSave(t, a, plan)
	poolLedger(t, a, first, "one", time.Now(), 12)
	batch := withPoolUsageSnapshot(ctx)
	initial, _, err := a.quotaUsage(batch, first, plan)
	if err != nil {
		t.Fatal(err)
	}
	poolLedger(t, a, second, "two", time.Now(), 18)
	same, _, err := a.quotaUsage(batch, second, plan)
	if err != nil || same.Total != initial.Total {
		t.Fatal("same batch observed different pool snapshots", initial, same, err)
	}
	fresh, _, err := a.quotaUsage(withPoolUsageSnapshot(ctx), second, plan)
	if err != nil || fresh.Total != 30 {
		t.Fatal("new batch reused stale pool usage", fresh, err)
	}
	member, _ := a.DB.UserByID(ctx, first.OwnerID)
	token, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	r := controllerRequest(t, a.Handler(), "GET", "/api/collections/subscriptions", token, nil)
	requireStatus(t, r, 200)
	body := r.Body.String()
	if strings.Contains(body, second.ID) || strings.Contains(body, second.OwnerID) || strings.Contains(body, text(second.Data, "credentialEmail")) || strings.Contains(body, `"members":`) {
		t.Fatal("pool projection leaked another member", body)
	}
	var out struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != 1 || number(out.Rows[0], "poolUsedBytes") != 30 || number(out.Rows[0], "poolRemainingBytes") != 70 || text(out.Rows[0], "trafficMode") != "shared" {
		t.Fatal("pool aggregate absent", body)
	}
	admin, _ := a.DB.UserByID(ctx, "admin")
	adminToken, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	for _, endpoint := range []string{"/api/members/management", "/api/collections/plans", "/api/collections/subscriptions/" + first.ID} {
		r := controllerRequest(t, a.Handler(), "GET", endpoint, adminToken, nil)
		requireStatus(t, r, 200)
		if !strings.Contains(r.Body.String(), `"poolUsedBytes":30`) {
			t.Fatal("projection missing", endpoint, r.Body.String())
		}
	}
}

func TestTrafficPoolPlanSaveIsAtomicAndValidatesMode(t *testing.T) {
	a, sub := subscriptionFixture(t)
	defer a.Close()
	ctx := context.Background()
	plan, _ := a.DB.GetRecord(ctx, "plans", "plan")
	stale := plan
	plan.Data = clone(plan.Data)
	plan.Data["description"] = "newer"
	plan = poolSave(t, a, plan)
	stale.Data["trafficMode"] = "shared"
	if _, err := a.savePlanWithPool(ctx, stale); err == nil {
		t.Fatal("stale conversion accepted")
	}
	if _, err := a.DB.GetRecord(ctx, "_trafficPools", plan.ID); err != store.ErrNotFound {
		t.Fatal("failed conversion left partial pool", err)
	}
	for _, value := range []any{true, 1, "invalid"} {
		row := clone(plan.Data)
		row["trafficMode"] = value
		if err := a.validatePlanManagement(ctx, row); err == nil {
			t.Fatal("invalid traffic mode accepted", value)
		}
	}
	poolLedger(t, a, sub, "prior", time.Now(), 17)
	admin, _ := a.DB.UserByID(ctx, "admin")
	token, _ := a.Signer.Issue(admin.ID, admin.TokenVersion)
	row := clone(plan.Data)
	row["trafficMode"], row["recordVersion"], row["poolUsedBytes"] = "shared", plan.Version, 0
	r := controllerRequest(t, a.Handler(), "PUT", "/api/collections/plans/plan", token, map[string]any{"row": row})
	requireStatus(t, r, 200)
	if !strings.Contains(r.Body.String(), `"poolUsedBytes":17`) {
		t.Fatal("conversion did not include existing ledger", r.Body.String())
	}
	stored, _ := a.DB.GetRecord(ctx, "plans", "plan")
	if stored.Data["poolUsedBytes"] != nil {
		t.Fatal("client forged a persisted aggregate", fmt.Sprint(stored.Data))
	}
}
