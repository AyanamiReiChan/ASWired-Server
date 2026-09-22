package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestTrafficMinuteBucketsPreserveLedgerAndRequireAdmin(t *testing.T) {
	a, handler, adminToken := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "minute-member", Username: "minute-member", Role: "user", PasswordHash: "test-hash", TokenVersion: 1}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, err := a.Signer.Issue(member.ID, member.TokenVersion)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Minute)
	insert := func(id, owner, direction string, at time.Time, raw int64, factor float64, gap int) {
		t.Helper()
		_, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), id, "minute-server", "minute-sub", owner, "test", direction, raw, factor, float64(raw)*factor, at.UnixMilli(), gap, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("up", member.ID, "uplink", base.Add(-5*time.Minute), 1, 2, 0)
	insert("down", member.ID, "downlink", base.Add(-4*time.Minute-time.Millisecond), 511, 2, 0)
	insert("next", member.ID, "uplink", base.Add(-4*time.Minute), 1024, 2, 0)
	insert("gap", member.ID, "downlink", base.Add(-2*time.Minute), 10, 2, 1)
	insert("zero", member.ID, "downlink", base, 0, 2, 0)
	insert("other", "another-member", "downlink", base.Add(-5*time.Minute), 9999, 3, 0)
	insert("outside-hour", member.ID, "uplink", base.Add(-61*time.Minute), 5, 2, 0)
	insert("two-hours", member.ID, "uplink", base.Add(-2*time.Hour), 7, 2, 0)
	insert("yesterday", member.ID, "uplink", base.Add(-25*time.Hour), 13, 2, 0)
	insert("future", member.ID, "uplink", base.Add(time.Hour), 1000000, 2, 0)
	read := func(token, query string) map[string]any {
		t.Helper()
		response := controllerRequest(t, handler, http.MethodGet, "/api/traffic?"+query, token, nil)
		requireStatus(t, response, http.StatusOK)
		return responseMap(t, response)
	}
	admin := read(adminToken, "range=1h&interval=1m")
	if text(admin, "interval") != "1m" || number(admin, "bucketSeconds") != 60 || text(admin, "unit") != "GiB" || text(admin, "scope") != "raw-proxy" {
		t.Fatalf("invalid metadata: %v", admin)
	}
	end := time.UnixMilli(int64(number(admin, "to")))
	expectedStart := end.Truncate(time.Minute).Add(-59 * time.Minute).UnixMilli()
	if int64(number(admin, "from")) != expectedStart {
		t.Fatalf("invalid minute window: %v", admin)
	}
	rows := admin["series"].([]any)
	if len(rows) != 4 {
		t.Fatalf("invented or lost buckets: %v", rows)
	}
	first := rows[0].(map[string]any)
	if int64(number(first, "at")) != base.Add(-5*time.Minute).UnixMilli() || number(first, "up")*gib != 1 || number(first, "down")*gib != 10510 {
		t.Fatalf("same-minute data lost: %v", first)
	}
	stamp, err := time.Parse(time.RFC3339, text(first, "time"))
	if err != nil || stamp.UnixMilli() != int64(number(first, "at")) {
		t.Fatalf("invalid timestamp: %v", first)
	}
	if number(rows[1].(map[string]any), "total")*gib != 1024 || !boolean(rows[2].(map[string]any), "gap") || number(rows[3].(map[string]any), "total") != 0 {
		t.Fatalf("boundary, gap or actual zero lost: %v", rows)
	}
	for _, query := range []string{"range=1h&interval=1m", "range=30d"} {
		requireStatus(t, controllerRequest(t, handler, http.MethodGet, "/api/traffic?"+query, memberToken, nil), http.StatusForbidden)
	}
	sum := func(result map[string]any) float64 {
		total := float64(0)
		for _, row := range result["series"].([]any) {
			total += number(row.(map[string]any), "total") * gib
		}
		return total
	}
	if sum(admin) != 11545 {
		t.Fatalf("incorrect raw totals: %v", sum(admin))
	}
	for _, interval := range []string{"6h", "24h"} {
		result := read(adminToken, "range="+interval+"&interval=1m")
		if sum(result) != 11557 {
			t.Fatalf("incorrect %s total: %v", interval, result)
		}
	}
	daily := read(adminToken, "range=30d")
	if text(daily, "interval") != "1d" || number(daily, "days") != 30 || sum(daily) != 11570 {
		t.Fatalf("daily totals changed: %v", daily)
	}
	for _, row := range daily["series"].([]any) {
		if len(text(row.(map[string]any), "date")) != 10 {
			t.Fatalf("daily date format changed: %v", row)
		}
	}
}

func TestTrafficMinuteEmptyRangeAndValidation(t *testing.T) {
	_, handler, token := controllerFixture(t)
	for _, query := range []string{"range=1h&interval=1m", "range=6h&interval=1m", "range=24h&interval=1m"} {
		response := controllerRequest(t, handler, http.MethodGet, "/api/traffic?"+query, token, nil)
		requireStatus(t, response, http.StatusOK)
		result := responseMap(t, response)
		if len(result["series"].([]any)) != 0 || !boolean(result, "incomplete") {
			t.Fatalf("empty history fabricated: %v", result)
		}
	}
	for _, query := range []string{"range=7d&interval=1m", "range=30d&interval=1m", "interval=1m", "range=1h", "range=1h&interval=1s", "range=1h&interval=1m&days=1", "range=25h&interval=1m", "range=30d&interval=unknown"} {
		requireStatus(t, controllerRequest(t, handler, http.MethodGet, "/api/traffic?"+query, token, nil), http.StatusBadRequest)
	}
	requireStatus(t, controllerRequest(t, handler, http.MethodGet, "/api/traffic?range=1h&interval=1m", "", nil), http.StatusUnauthorized)
}
