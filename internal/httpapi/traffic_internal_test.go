package httpapi

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func saveTrafficTestServer(t *testing.T, a *App, id string) {
	t.Helper()
	if _, err := a.DB.SaveRecord(context.Background(), store.Record{Collection: "servers", ID: id, Data: map[string]any{"name": id}}); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficInternalClassificationProjectsHistoryWithoutRebilling(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	h := a.Handler()
	token, err := a.Signer.Issue("admin", 0)
	if err != nil {
		t.Fatal(err)
	}
	saveTrafficTestServer(t, a, "other-server")
	insert := func(id, server, owner, subscription, email, direction string, raw, factor int, gap int, reason string) {
		t.Helper()
		_, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), id, server, subscription, owner, email, direction, raw, factor, raw*factor, time.Now().Add(-time.Minute).UnixMilli(), gap, reason)
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("internal-up", "server", "", "", "hop-account", "uplink", 100, 1, 1, "unassigned_email")
	insert("internal-down", "server", "", "", "hop-account", "downlink", 200, 1, 1, "counter_decreased")
	insert("different-server", "other-server", "", "", "hop-account", "downlink", 50, 1, 1, "unassigned_email")
	insert("unknown-prefix", "server", "", "", "chain-unconfirmed", "downlink", 25, 1, 1, "unassigned_email")
	insert("member", "server", sub.OwnerID, sub.ID, text(sub.Data, "credentialEmail"), "downlink", 11, 3, 0, "")
	read := func(path string) map[string]any {
		t.Helper()
		res := controllerRequest(t, h, http.MethodGet, path, token, nil)
		requireStatus(t, res, 200)
		return responseMap(t, res)
	}
	before := read("/api/traffic")
	syncPath := "/api/traffic?sync=1"
	syncBefore := read(syncPath)
	post := controllerRequest(t, h, http.MethodPost, "/api/traffic/internal-transfers", token, map[string]any{"serverId": "server", "email": "hop-account", "name": "Entry → Exit", "sourceServerId": "other-server"})
	requireStatus(t, post, 200)
	mapping := responseMap(t, post)
	id := text(mapping, "id")
	if id != trafficPairID("server", "hop-account") {
		t.Fatal("unstable classification id", mapping)
	}
	post = controllerRequest(t, h, http.MethodPost, "/api/traffic/internal-transfers", token, map[string]any{"serverId": "server", "email": "hop-account", "name": "Renamed route", "sourceServerId": "other-server"})
	requireStatus(t, post, 200)
	items := read("/api/traffic/internal-transfers")["items"].([]any)
	if len(items) != 1 || text(items[0].(map[string]any), "id") != id || text(items[0].(map[string]any), "name") != "Renamed route" {
		t.Fatal("upsert duplicated or failed to update pair", items)
	}
	after := read("/api/traffic")
	if !reflect.DeepEqual(before["servers"], after["servers"]) || !reflect.DeepEqual(before["series"], after["series"]) || number(before, "gaps") != number(after, "gaps") {
		t.Fatal("classification changed original totals or hid historical gaps", before, after)
	}
	internal := after["internal"].([]any)
	if len(internal) != 1 {
		t.Fatal("missing internal row", after)
	}
	row := internal[0].(map[string]any)
	if text(row, "classificationId") != id || text(row, "serverName") != "Test Server" || text(row, "sourceServerName") != "other-server" || number(row, "up") != 100 || number(row, "down") != 200 || number(row, "used") != 300/gib || row["limit"] != nil {
		t.Fatal("incorrect internal projection", row)
	}
	unknown := after["unassigned"].([]any)
	if len(unknown) != 2 {
		t.Fatal("different server or email prefix was auto-classified", unknown)
	}
	memberTotals := map[string]float64{}
	for _, value := range after["members"].([]any) {
		row := value.(map[string]any)
		memberTotals[text(row, "id")] = number(row, "up") + number(row, "down")
	}
	if memberTotals[""] != 75 || memberTotals[sub.OwnerID] != 33 {
		t.Fatal("unknown aggregate or weighted member usage changed", memberTotals)
	}
	usage, err := a.DB.SubscriptionUsage(ctx, sub.ID, 0, time.Now().Add(time.Hour).UnixMilli())
	if err != nil || usage.Total != 33 {
		t.Fatal("subscription was rebilled", usage, err)
	}
	var count int
	var rawSum, weightedSum float64
	if err := a.DB.DB().QueryRow(`SELECT COUNT(*),SUM(raw_bytes),SUM(weighted_bytes) FROM traffic_ledger`).Scan(&count, &rawSum, &weightedSum); err != nil || count != 5 || rawSum != 386 || weightedSum != 408 {
		t.Fatal("ledger changed", count, rawSum, weightedSum, err)
	}
	synced := read(syncPath)
	data := synced["data"].(map[string]any)
	if len(data["internal"].(map[string]any)) != 1 || len(data["unassigned"].(map[string]any)) != 2 {
		t.Fatal("sync arrays were not indexed", data)
	}
	delta := read(syncPath + "&cursor=" + text(syncBefore, "cursor"))
	if !strings.Contains(string(mustJSON(delta["changes"])), id) {
		t.Fatal("historical reclassification missing in sync changes", delta)
	}
	// A later subscription can acquire the same email. Its owned rows must
	// remain member usage even while the older unowned rows are classified.
	insert("later-owned", "server", sub.OwnerID, sub.ID, "hop-account", "uplink", 7, 3, 0, "")
	ownedAfter := read("/api/traffic")
	if number(ownedAfter["internal"].([]any)[0].(map[string]any), "up") != 100 {
		t.Fatal("owned sample moved to internal transfer", ownedAfter)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/traffic/internal-transfers/"+id, token, nil), 200)
	deleted := read(syncPath + "&cursor=" + text(synced, "cursor"))
	if !strings.Contains(string(mustJSON(deleted["removed"])), id) {
		t.Fatal("deleted internal row missing sync tombstone", deleted)
	}
	restored := read("/api/traffic")
	if len(restored["internal"].([]any)) != 0 || len(restored["unassigned"].([]any)) != 3 {
		t.Fatal("deleting classification did not restore unassigned history", restored)
	}
}

func TestTrafficInternalAPIValidationAndPermissions(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	saveTrafficTestServer(t, a, "server")
	member := store.User{ID: "traffic-member", Username: "traffic-member", Role: "user", PasswordHash: "test", TokenVersion: 1}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		path := "/api/traffic/internal-transfers"
		if method == http.MethodDelete {
			path += "/missing"
		}
		for _, auth := range []struct {
			token string
			code  int
		}{{"", 401}, {memberToken, 403}} {
			requireStatus(t, controllerRequest(t, h, method, path, auth.token, map[string]any{}), auth.code)
		}
	}
	for _, input := range []map[string]any{
		{}, {"serverId": "missing", "email": "hop", "name": "route"},
		{"serverId": "server", "email": "hop>>>traffic", "name": "route"},
		{"serverId": "server", "email": "hop\naccount", "name": "route"},
		{"serverId": "server", "email": "hop", "name": " "},
		{"serverId": "server", "email": "hop", "name": "route", "sourceServerId": "missing"},
	} {
		requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/traffic/internal-transfers", token, input), 400)
	}
	for _, record := range []store.Record{
		{Collection: "subscriptions", ID: "member-sub", OwnerID: member.ID, Data: map[string]any{"planId": "plan", "credentialEmail": "member-email"}},
		{Collection: "inbounds", ID: "inbound", Data: map[string]any{"serverId": "server"}},
	} {
		if _, err := a.DB.SaveRecord(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.DB.DB().Exec(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES('old-owned','server','deleted-sub','','old-email','uplink',1,1,1,1,0,'')`); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"member-email", "member-email.inbound", "old-email"} {
		requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/traffic/internal-transfers", token, map[string]any{"serverId": "server", "email": email, "name": "route"}), 409)
	}
	readOnly := controllerRequest(t, h, http.MethodPost, "/api/actions", token, map[string]any{"action": "token.create", "params": map[string]any{"name": "traffic read", "scopes": []string{"read"}}})
	requireStatus(t, readOnly, 200)
	readToken := text(responseMap(t, readOnly), "token")
	requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/traffic/internal-transfers", readToken, nil), 200)
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/traffic/internal-transfers", readToken, map[string]any{}), 403)
	requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/traffic/internal-transfers/missing", readToken, nil), 403)
}

func TestTrafficInternalAccountingKeepsRealGapsAndSkipsZeroDelta(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	saveTrafficTestServer(t, a, "other-server")
	email := "hop-account"
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: trafficInternalCollection, ID: trafficPairID("server", email), Data: map[string]any{"serverId": "server", "email": email, "name": "Test route"}}); err != nil {
		t.Fatal(err)
	}
	key := "user>>>" + email + ">>>traffic>>>uplink"
	base := time.Now().Add(-time.Minute).UnixMilli()
	for i, sample := range []struct {
		generation string
		value      int64
	}{{"g1", 100}, {"g1", 100}, {"g2", 10}, {"g2", 5}} {
		a.accountStats(ctx, "server", map[string]any{"timestamp": base + int64(i)*1000, "generation": sample.generation, "counters": map[string]any{key: sample.value}})
	}
	rows, err := a.DB.DB().Query(`SELECT raw_bytes,gap,gap_reason,owner_id,subscription_id,factor FROM traffic_ledger WHERE server_id='server' ORDER BY sampled_at`)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	var total int64
	for rows.Next() {
		var raw int64
		var gap int
		var reason, owner, subscription string
		var factor float64
		if err := rows.Scan(&raw, &gap, &reason, &owner, &subscription, &factor); err != nil {
			t.Fatal(err)
		}
		if factor != 1 || owner != "" || subscription != "" || (len(reasons) == 0 && gap != 0) || (len(reasons) > 0 && gap != 1) {
			t.Fatal("invalid internal accounting", raw, gap, reason, owner, subscription, factor)
		}
		total += raw
		reasons = append(reasons, reason)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if total != 115 || !reflect.DeepEqual(reasons, []string{"", "core_generation_changed", "counter_decreased"}) {
		t.Fatal("zero delta persisted or real gap was lost", total, reasons)
	}
	a.accountStats(ctx, "other-server", map[string]any{"timestamp": base, "generation": "g1", "counters": map[string]any{key: int64(9)}})
	var reason string
	if err := a.DB.DB().QueryRow(`SELECT gap_reason FROM traffic_ledger WHERE server_id='other-server'`).Scan(&reason); err != nil || reason != "unassigned_email" {
		t.Fatal("same email on another server was incorrectly classified", reason, err)
	}
	usage, err := a.DB.SubscriptionUsage(ctx, sub.ID, 0, time.Now().UnixMilli())
	if err != nil || usage.Total != 0 {
		t.Fatal("internal traffic charged a subscription", usage, err)
	}
}
