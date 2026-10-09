package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestMemberTrafficAccessValidationAndEmpty(t *testing.T) {
	a, h, adminToken := controllerFixture(t)
	ctx := context.Background()
	member := store.User{ID: "traffic-member", Username: "traffic-member", Role: "user", PasswordHash: "hash"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, 0)
	path := "/api/members/" + member.ID + "/traffic"
	requireStatus(t, controllerRequest(t, h, http.MethodGet, path, "", nil), 401)
	requireStatus(t, controllerRequest(t, h, http.MethodGet, path, memberToken, nil), 403)
	requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/members/missing/traffic", adminToken, nil), 404)
	for _, query := range []string{"range=1h", "range=all", "range=cycle&range=24h", "days=1", "range=24h&start=0"} {
		requireStatus(t, controllerRequest(t, h, http.MethodGet, path+"?"+query, adminToken, nil), 400)
	}
	for _, query := range []string{"", "?range=cycle", "?range=24h", "?range=7d", "?range=30d"} {
		response := controllerRequest(t, h, http.MethodGet, path+query, adminToken, nil)
		requireStatus(t, response, 200)
		out := responseMap(t, response)
		if len(out["rows"].([]any)) != 0 || number(out["totals"].(map[string]any), "totalBytes") != 0 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("empty scope fabricated traffic or cached private response", out)
		}
		if text(out, "range") == "cycle" && (out["from"] != nil || len(out["windows"].([]any)) != 0) {
			t.Fatal("empty cycle fabricated dates", out)
		}
	}
	if _, err := a.DB.DB().ExecContext(ctx, `ALTER TABLE traffic_ledger RENAME TO unavailable_traffic_ledger`); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodGet, path+"?range=24h", adminToken, nil), 500)
}

func TestMemberTrafficIdentityHistorySharedAndWindows(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	old := now.Add(-40 * 24 * time.Hour)
	for _, id := range []string{"alice", "bob"} {
		if err := a.DB.CreateUser(ctx, store.User{ID: id, Username: id, Role: "user", PasswordHash: "hash"}); err != nil {
			t.Fatal(err)
		}
	}
	save := func(collection, id, owner string, data map[string]any) {
		t.Helper()
		if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: collection, ID: id, OwnerID: owner, Data: data}); err != nil {
			t.Fatal(err)
		}
		// Fixture history predates the query. created_at is a separate plaintext
		// metadata column; all actual record payloads still use the normal store.
		if _, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`UPDATE records SET created_at=? WHERE collection=? AND id=?`), old.Format(time.RFC3339Nano), collection, id); err != nil {
			t.Fatal(err)
		}
	}
	save("plans", "shared", "", map[string]any{"trafficMode": "shared", "limit": 100})
	save("servers", "jp", "", map[string]any{"name": "Japan", "multiplier": 100})
	save("servers", "us", "", map[string]any{"name": "US"})
	save("inbounds", "jp-a", "", map[string]any{"name": "Japan A", "serverId": "jp", "multiplier": 100})
	save("inbounds", "jp-b", "", map[string]any{"name": "Japan B", "serverId": "jp", "status": "禁用"})
	save("inbounds", "us-a", "", map[string]any{"name": "US A", "serverId": "us"})
	save("nodes", "inbound-jp-a", "", map[string]any{"name": "Custom Japan A", "managedInbound": true, "inboundId": "jp-a", "serverId": "jp"})
	save("subscriptions", "alice-a", "alice", map[string]any{"name": "Alice Shared", "planId": "shared", "credentialEmail": "private-base", "cycleStart": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339Nano), "cycleEnd": now.Add(20 * 24 * time.Hour).Format(time.RFC3339Nano)})
	save("subscriptions", "alice-b", "alice", map[string]any{"name": "Alice Earlier", "planId": "other", "credentialEmail": "private-second", "cycleStart": now.Add(-6 * time.Hour).Format(time.RFC3339Nano), "cycleEnd": now.Add(-time.Hour).Format(time.RFC3339Nano)})
	save("subscriptions", "bob-a", "bob", map[string]any{"planId": "shared", "credentialEmail": "bob-base", "cycleStart": now.Add(-2 * 24 * time.Hour).Format(time.RFC3339Nano)})
	insert := func(id, sub, owner, server, email, direction string, raw int64, factor float64, at time.Time, gap int) {
		t.Helper()
		if _, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), id, server, sub, owner, email, direction, raw, factor, float64(raw)*factor, at.UnixMilli(), gap, ""); err != nil {
			t.Fatal(err)
		}
	}
	insert("a-up", "alice-a", "alice", "jp", "private-base.jp-a", "uplink", 10, 2, now.Add(-2*24*time.Hour), 0)
	insert("a-down", "alice-a", "alice", "jp", "private-base.jp-a", "downlink", 30, 0.5, now.Add(-2*time.Hour), 0)
	insert("b-down", "alice-a", "alice", "jp", "private-base.jp-b", "downlink", 20, 3, now.Add(-2*time.Hour), 0)
	insert("us-down", "alice-a", "alice", "us", "private-base.us-a", "downlink", 5, 1, now.Add(-2*time.Hour), 0)
	insert("unbilled", "alice-a", "alice", "us", "private-base.us-a", "downlink", 13, 0, now.Add(-2*time.Hour), 0)
	insert("old-credential", "alice-a", "alice", "jp", "old-private-base.jp-a", "uplink", 7, 1, now.Add(-2*time.Hour), 1)
	insert("base-only", "alice-a", "alice", "jp", "private-base", "downlink", 3, 1, now.Add(-2*time.Hour), 0)
	insert("deleted-inbound", "alice-a", "alice", "jp", "private-base.deleted", "downlink", 4, 1, now.Add(-2*time.Hour), 0)
	insert("wrong-server", "alice-a", "alice", "us", "private-base.jp-a", "downlink", 6, 1, now.Add(-2*time.Hour), 0)
	insert("second-start", "alice-b", "alice", "jp", "private-second.jp-a", "downlink", 8, 1, now.Add(-6*time.Hour), 0)
	insert("second-before", "alice-b", "alice", "jp", "private-second.jp-a", "downlink", 80, 1, now.Add(-6*time.Hour-time.Millisecond), 0)
	insert("second-end", "alice-b", "alice", "jp", "private-second.jp-a", "downlink", 90, 1, now.Add(-time.Hour), 0)
	insert("first-before", "alice-a", "alice", "jp", "private-base.jp-a", "downlink", 100, 1, now.Add(-2*24*time.Hour-time.Millisecond), 0)
	insert("future", "alice-a", "alice", "jp", "private-base.jp-a", "downlink", 1000, 1, now, 0)
	insert("retired-sub", "deleted-sub", "alice", "jp", "private-base.jp-a", "downlink", 11, 1, now.Add(-3*time.Hour), 0)
	insert("missing-server", "deleted-sub", "alice", "retired-server", "old", "downlink", 12, 1, now.Add(-3*time.Hour), 0)
	insert("bob", "bob-a", "bob", "jp", "bob-base.jp-a", "downlink", 9999, 1, now.Add(-2*time.Hour), 0)
	insert("unassigned", "", "", "jp", "private-base.jp-a", "downlink", 9999, 1, now.Add(-2*time.Hour), 0)
	read := func(rangeName string) map[string]any {
		t.Helper()
		var before, after int64
		if err := a.DB.DB().QueryRowContext(ctx, `SELECT total_changes()`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		out, err := a.memberTrafficSnapshot(ctx, "alice", rangeName, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.DB.DB().QueryRowContext(ctx, `SELECT total_changes()`).Scan(&after); err != nil || before != after {
			t.Fatal("read-only distribution changed stored state", before, after, err)
		}
		raw, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-base", "private-second", "bob-base", "credentialEmail", "token", "password", "uuid"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("private credentials leaked into distribution", secret)
			}
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	cycle := read("cycle")
	totals := cycle["totals"].(map[string]any)
	if number(totals, "totalBytes") != 128 || number(totals, "rawTotalBytes") != 106 || number(totals, "uploadBytes") != 27 || !boolean(totals, "gap") || !boolean(cycle, "hasUnmappedTraffic") {
		t.Fatal("personal shared-plan cycle totals wrong", cycle)
	}
	rows := cycle["rows"].([]any)
	if len(rows) != 5 || text(rows[0].(map[string]any), "inboundId") != "jp-b" || number(rows[0].(map[string]any), "totalBytes") != 60 {
		t.Fatal("node ordering or disabled-node traffic lost", rows)
	}
	var sumShare float64
	foundNamed := false
	for _, value := range rows {
		row := value.(map[string]any)
		sumShare += number(row, "share")
		if text(row, "inboundId") == "jp-a" {
			foundNamed = true
			if text(row, "nodeName") != "Custom Japan A" || number(row, "totalBytes") != 43 {
				t.Fatal("managed display name or merged personal subscriptions lost", row)
			}
		}
	}
	if !foundNamed || sumShare < 99.999999 || sumShare > 100.000001 || len(cycle["windows"].([]any)) != 2 {
		t.Fatal("distribution percentages or cycle detail wrong", cycle)
	}
	day := read("24h")
	if number(day["totals"].(map[string]any), "totalBytes") != 301 || text(day, "scope") != "owner-history" {
		t.Fatal("fixed window lost retired subscriptions or applied personal cycle", day)
	}
	for _, span := range []string{"7d", "30d"} {
		out := read(span)
		if number(out["totals"].(map[string]any), "totalBytes") != 421 {
			t.Fatal("long fixed window wrong", out)
		}
	}
	// An inbound recreated with the same ID must not label old samples as the
	// current node, even when the credential string happens to match exactly.
	if _, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`UPDATE records SET created_at=? WHERE collection='inbounds' AND id='jp-a'`), now.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	rebuilt := read("cycle")
	if number(rebuilt["totals"].(map[string]any), "totalBytes") != 128 {
		t.Fatal("recreated metadata erased recorded usage", rebuilt)
	}
	for _, value := range rebuilt["rows"].([]any) {
		if text(value.(map[string]any), "inboundId") == "jp-a" {
			t.Fatal("recreated inbound adopted old traffic")
		}
	}
}

func TestMemberTrafficRejectsOverflow(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"one", "two"} {
		if _, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,'server',?,'owner',?,'downlink',1,1,?,?,0,'')`), id, id, id, 1e308, now.Add(-time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.memberTrafficSnapshot(ctx, "owner", "24h", now); err == nil {
		t.Fatal("overflow would return invalid JSON or an invented zero")
	}
}
