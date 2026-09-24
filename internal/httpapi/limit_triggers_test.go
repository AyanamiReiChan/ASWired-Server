package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func triggerTestEvent(id, user, server, rule, kind string, at, until time.Time, speed float64) store.Record {
	return store.Record{
		Collection: "_limitEvents", ID: id, OwnerID: user, CreatedAt: at.Add(time.Millisecond), UpdatedAt: at.Add(time.Millisecond),
		Data: map[string]any{"userId": user, "serverId": server, "ruleId": rule, "type": kind, "at": at.UTC().Format(time.RFC3339Nano), "until": until.UTC().Format(time.RFC3339Nano), "limitMbps": speed, "sampleMbps": 90, "source": "global", "reason": "sustained"},
	}
}

func triggerTestRows(result limitTriggerResponse) map[string]limitTriggerRow {
	rows := map[string]limitTriggerRow{}
	for _, row := range result.Rows {
		rows[row.ID] = row
	}
	return rows
}

func readTriggerTestResponse(t *testing.T, a *App) limitTriggerResponse {
	t.Helper()
	w := httptest.NewRecorder()
	a.limitTriggers(w, httptest.NewRequest("GET", "/api/limits/triggers", nil))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var result limitTriggerResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLimitTriggersBehaviorCyclesUseRuntimeAndMatchingRelease(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	start, end := now.Add(-time.Minute), now.Add(time.Minute)
	active := triggerTestEvent("active", "user", "node", "global/active", "triggered", start, end, 30)
	released := triggerTestEvent("released", "user", "node", "global/released", "triggered", start, end, 20)
	release := triggerTestEvent("release-event", "user", "node", "global/released", "released", now.Add(-time.Second), end, 20)
	release.Data["reason"] = "configuration_changed"
	expired := triggerTestEvent("expired", "other", "node", "global/expired", "triggered", start, now.Add(-time.Second), 5)
	missing := triggerTestEvent("missing-state", "other", "node", "global/missing", "triggered", start, end, 5)
	mismatch := triggerTestEvent("other-cycle", "user", "node", "global/active", "triggered", start.Add(-time.Hour), end.Add(time.Minute), 30)
	wrongRelease := triggerTestEvent("other-release-cycle", "user", "node", "global/active", "released", now, end.Add(2*time.Minute), 30)
	stale := triggerTestEvent("stale-state", "user", "node", "global/stale", "triggered", start, end, 5)
	wrongSpeed := triggerTestEvent("wrong-speed", "user", "node", "global/speed", "triggered", start, end, 6)
	future := triggerTestEvent("future", "user", "node", "global/future", "triggered", now.Add(time.Minute), end.Add(time.Minute), 5)
	state := behaviorState{At: now.UnixMilli(), Rules: map[string]behaviorProgress{
		"global/active":   {Until: end.UnixMilli(), LimitMbps: 30},
		"global/released": {Until: end.UnixMilli(), LimitMbps: 20},
		"global/speed":    {Until: end.UnixMilli(), LimitMbps: 5},
		"global/future":   {Until: end.Add(time.Minute).UnixMilli(), LimitMbps: 5},
	}}
	collections := map[string][]store.Record{
		"_limitEvents": {active, released, release, expired, missing, mismatch, wrongRelease, stale, wrongSpeed, future},
		"_limitState":  {{ID: "node/user", OwnerID: "user", Data: stateData(state)}},
	}
	result := buildLimitTriggers(collections, nil, now)
	rows := triggerTestRows(result)
	for id, want := range map[string]string{"active": "active", "released": "released", "expired": "expired", "missing-state": "unknown", "other-cycle": "unknown", "stale-state": "unknown", "wrong-speed": "unknown", "future": "unknown"} {
		if rows[id].Status != want {
			t.Errorf("%s status %q, want %q", id, rows[id].Status, want)
		}
	}
	if len(result.Rows) != 8 || result.Summary != (limitTriggerSummary{TriggerCount: 8, UserCount: 2, ActiveCount: 1, ActiveUserCount: 1}) {
		t.Fatalf("non-trigger rows or wrong summary: %+v", result)
	}
	if rows["released"].ReleasedAt != text(release.Data, "at") || rows["released"].ReleaseReason != "configuration_changed" {
		t.Fatalf("lost release information: %+v", rows["released"])
	}
	if result.Rows[0].ID != "future" || result.Rows[len(result.Rows)-1].ID != "other-cycle" {
		t.Fatalf("not sorted by actual trigger timestamp: %+v", result.Rows)
	}
}

func TestLimitTriggersQuotaCyclesAndConcurrentSnapshot(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	firstAt, releaseAt, latestAt := now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute)
	first := triggerTestEvent("first", "user", "", "sub", "quota_triggered", firstAt, time.UnixMilli(0), 5)
	released := triggerTestEvent("quota-release", "user", "", "sub", "quota_released", releaseAt, time.UnixMilli(0), 0)
	released.Data["reason"] = "quota_available"
	latest := triggerTestEvent("latest", "user", "", "sub", "quota_triggered", latestAt, time.UnixMilli(0), 5)
	quota := store.Record{ID: "sub", OwnerID: "user", UpdatedAt: latestAt.Add(time.Microsecond), Data: map[string]any{"overQuota": true, "quotaSpeedMbps": 5}}
	collections := map[string][]store.Record{"_limitEvents": {first, released, latest}, "_quotaState": {quota}}
	rows := triggerTestRows(buildLimitTriggers(collections, nil, now))
	if rows["first"].Status != "released" || rows["latest"].Status != "active" || rows["latest"].Until != "" {
		t.Fatalf("quota cycle mismatch: %+v", rows)
	}
	collections["_limitEvents"] = []store.Record{first, latest}
	rows = triggerTestRows(buildLimitTriggers(collections, nil, now))
	if rows["first"].Status != "unknown" || rows["latest"].Status != "active" {
		t.Fatalf("same-speed old trigger counted as current: %+v", rows)
	}
	for _, item := range []struct {
		name string
		edit func(*store.Record)
	}{
		{"different owner", func(r *store.Record) { r.OwnerID = "other" }},
		{"different speed", func(r *store.Record) { r.Data["quotaSpeedMbps"] = 8 }},
		{"released quota", func(r *store.Record) { r.Data["overQuota"] = false }},
		{"old state", func(r *store.Record) { r.UpdatedAt = latestAt.Add(-time.Second) }},
		{"newer state after event batch", func(r *store.Record) { r.UpdatedAt = now }},
	} {
		t.Run(item.name, func(t *testing.T) {
			q := quota
			q.Data = map[string]any{"overQuota": true, "quotaSpeedMbps": 5}
			item.edit(&q)
			collections["_quotaState"] = []store.Record{q}
			rows := triggerTestRows(buildLimitTriggers(collections, nil, now))
			if rows["latest"].Status != "unknown" {
				t.Fatalf("unrelated quota state counted active: %+v", rows["latest"])
			}
		})
	}
}

func TestLimitTriggersIncompleteIdentityAndStaleStateAreNeverActive(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	at, until := now.Add(-time.Second), now.Add(time.Minute)
	event := triggerTestEvent("event", "user", "node", "global/rule", "triggered", at, until, 5)
	state := store.Record{ID: "node/user", OwnerID: "user", Data: stateData(behaviorState{At: now.UnixMilli(), Rules: map[string]behaviorProgress{"global/rule": {Until: until.UnixMilli(), LimitMbps: 5}}})}
	state.OwnerID = "different-user"
	collections := map[string][]store.Record{"_limitEvents": {event}, "_limitState": {state}}
	if result := buildLimitTriggers(collections, nil, now); result.Rows[0].Status != "unknown" {
		t.Fatalf("state belonging to another user made a trigger active: %+v", result)
	}
	state.OwnerID = "user"
	state.Data["at"] = at.Add(-time.Millisecond).UnixMilli()
	collections["_limitState"] = []store.Record{state}
	if result := buildLimitTriggers(collections, nil, now); result.Rows[0].Status != "unknown" {
		t.Fatalf("state older than the trigger made it active: %+v", result)
	}
	event.OwnerID, event.Data["userId"] = "", ""
	state.ID, state.OwnerID = "node/", ""
	state.Data["at"] = now.UnixMilli()
	collections["_limitEvents"], collections["_limitState"] = []store.Record{event}, []store.Record{state}
	if result := buildLimitTriggers(collections, nil, now); result.Rows[0].Status != "unknown" || result.Summary.UserCount != 0 || result.Summary.ActiveCount != 0 {
		t.Fatalf("broken legacy identity counted as a user or active limit: %+v", result)
	}
}

func TestLimitTriggersWhitelistsSnapshotsNamesAndKeepsLegacyHistory(t *testing.T) {
	now := time.Now()
	snapshot := map[string]any{"id": "global/rule", "kind": "behavior", "type": "sustained", "thresholdMbps": 80, "durationSeconds": 600, "limitMbps": 30, "penaltySeconds": 600, "notify": false, "password": "snapshot-secret", "script": map[string]any{"token": "nested-secret"}}
	event := triggerTestEvent("new", "user", "node", "global/rule", "triggered", now.Add(-time.Minute), now.Add(time.Minute), 30)
	event.Data["rule"], event.Data["token"], event.Data["notificationStatus"] = snapshot, "event-secret", "notification-secret"
	event.Data["source"] = "plan:plan"
	legacy := triggerTestEvent("legacy", "user", "node", "global/legacy", "triggered", now.Add(-time.Hour), now.Add(-time.Minute), 5)
	collections := map[string][]store.Record{
		"_limitEvents": {event, legacy},
		"members":      {{ID: "user", Data: map[string]any{"name": "Display name", "token": "member-secret", "behaviorLimits": map[string]any{"password": "current-policy-secret"}}}},
		"servers":      {{ID: "node", Data: map[string]any{"name": "Display node", "token": "node-secret"}}},
		"plans":        {{ID: "plan", Data: map[string]any{"name": "Display plan", "password": "plan-secret"}}},
	}
	result := buildLimitTriggers(collections, []store.User{{ID: "user", Username: "account", PasswordHash: "hash-secret"}}, now)
	rows := triggerTestRows(result)
	if rows["new"].UserName != "Display name" || rows["new"].ServerName != "Display node" || rows["new"].SourceName != "Display plan" || rows["new"].Rule == nil || *rows["new"].Rule.ThresholdMbps != 80 {
		t.Fatalf("missing readable identity or saved rule: %+v", result)
	}
	if rows["legacy"].Rule != nil {
		t.Fatal("legacy event fabricated a snapshot from current rules")
	}
	raw, err := json.Marshal(result)
	if err != nil || strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "notificationStatus") {
		t.Fatalf("response leaks fields: %s, %v", raw, err)
	}
	if triggerSnapshot(map[string]any{"id": "bad", "limitMbps": "not-a-number"}) != nil {
		t.Fatal("accepted untyped historical parameters")
	}
	if triggerSnapshot(behaviorRule{ID: "global/struct", LimitMbps: 5}) == nil {
		t.Fatal("did not support rule structs before persistence")
	}
}

func TestLimitTriggersSortByEventTimeBoundRowsAndSummarizeReturnedRows(t *testing.T) {
	now := time.Now()
	collections := map[string][]store.Record{}
	for i := 0; i < 1001; i++ {
		id := fmt.Sprintf("trigger-%04d", i)
		// Reverse insertion timestamps to catch sorting by created_at or ID.
		event := triggerTestEvent(id, id, "node", id, "triggered", now.Add(-time.Duration(i+1)*time.Minute), now.Add(-time.Second), 5)
		event.CreatedAt = now.Add(time.Duration(i) * time.Second)
		collections["_limitEvents"] = append(collections["_limitEvents"], event)
	}
	result := buildLimitTriggers(collections, nil, now)
	if !result.Truncated || len(result.Rows) != 1000 || result.Rows[0].ID != "trigger-0000" || result.Rows[999].ID != "trigger-0999" || result.Summary != (limitTriggerSummary{TriggerCount: 1000, UserCount: 1000}) {
		t.Fatalf("incorrect pagination/summary: first=%s last=%s count=%d summary=%+v truncated=%v", result.Rows[0].ID, result.Rows[len(result.Rows)-1].ID, len(result.Rows), result.Summary, result.Truncated)
	}
	collections["_limitEvents"] = collections["_limitEvents"][:1000]
	if buildLimitTriggers(collections, nil, now).Truncated {
		t.Fatal("exactly 1000 rows incorrectly marked truncated")
	}
	if empty := buildLimitTriggers(map[string][]store.Record{"_effectiveLimits": {{ID: "user-node", Data: map[string]any{"limitMbps": 0}}}}, nil, now); empty.Rows == nil || len(empty.Rows) != 0 || empty.Summary.TriggerCount != 0 {
		t.Fatalf("untriggered effective state leaked into history: %+v", empty)
	}
}

func TestLimitTriggersRealBehaviorSnapshotAndReadDoesNotMutateState(t *testing.T) {
	a, sub, key, owners := limitFixture(t, []map[string]any{{"id": "saved", "type": "sustained", "thresholdMbps": 8, "durationSeconds": 5, "limitMbps": 2, "penaltySeconds": 600}})
	start := time.Now().Add(-10 * time.Second)
	ruleSample(a, key, owners, start, 0, "generation")
	ruleSample(a, key, owners, start.Add(5*time.Second), 5_000_000, "generation")
	ctx := context.Background()
	collections := []string{"_limitEvents", "_limitState", "_effectiveLimits", "_quotaState", "_policySync", "subscriptions", "_usage"}
	before := map[string][]store.Record{}
	for _, collection := range collections {
		var err error
		before[collection], err = a.DB.ListRecords(ctx, collection, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	result := readTriggerTestResponse(t, a)
	if len(result.Rows) != 1 || result.Rows[0].UserID != sub.OwnerID || result.Rows[0].Status != "active" || result.Rows[0].Rule == nil || *result.Rows[0].Rule.ThresholdMbps != 8 {
		t.Fatalf("real trigger not shown with saved condition: %+v", result)
	}
	for _, collection := range collections {
		after, err := a.DB.ListRecords(ctx, collection, "")
		if err != nil || !reflect.DeepEqual(before[collection], after) {
			t.Fatalf("history read mutated %s: %v", collection, err)
		}
	}
}

func TestLimitTriggersRealQuotaStateChronology(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, err := a.DB.GetRecord(ctx, "plans", "plan")
	if err != nil {
		t.Fatal(err)
	}
	a.noteQuotaState(ctx, sub, plan, true, 5)
	result := readTriggerTestResponse(t, a)
	if len(result.Rows) != 1 || result.Rows[0].Status != "active" || result.Rows[0].Rule == nil || result.Rows[0].Rule.Kind != "quota" || result.Rows[0].Until != "" {
		t.Fatalf("real quota trigger incorrect: %+v", result)
	}
	firstID := result.Rows[0].ID
	before, err := a.DB.GetRecord(ctx, "_quotaState", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.noteQuotaState(ctx, sub, plan, true, 5)
	after, err := a.DB.GetRecord(ctx, "_quotaState", sub.ID)
	if err != nil || before.Version != after.Version || !before.UpdatedAt.Equal(after.UpdatedAt) {
		t.Fatalf("unchanged quota cycle rewrote its timestamp: before=%v after=%v err=%v", before.UpdatedAt, after.UpdatedAt, err)
	}
	result = readTriggerTestResponse(t, a)
	if len(result.Rows) != 1 || result.Rows[0].ID != firstID || result.Rows[0].Status != "active" {
		t.Fatalf("unchanged quota cycle lost its active trigger: %+v", result)
	}
	a.noteQuotaState(ctx, sub, plan, false, 0)
	result = readTriggerTestResponse(t, a)
	if result.Rows[0].Status != "released" || result.Rows[0].ReleaseReason != "quota_available" {
		t.Fatalf("quota release missing: %+v", result)
	}
	a.noteQuotaState(ctx, sub, plan, true, 5)
	result = readTriggerTestResponse(t, a)
	rows := triggerTestRows(result)
	if len(result.Rows) != 2 || result.Summary.ActiveCount != 1 || rows[firstID].Status != "released" || result.Rows[0].Status != "active" || result.Rows[0].ID == firstID {
		t.Fatalf("same-speed new quota cycle mixed with previous cycle: %+v", result)
	}
}
