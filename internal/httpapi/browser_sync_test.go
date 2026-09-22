package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
	"time"
)

func TestBrowserStateDeltaIsolationDeletionAndExpiry(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	row, err := a.DB.SaveRecord(ctx, store.Record{Collection: "policies", ID: "large", Data: map[string]any{"name": "before", "content": strings.Repeat("fixture-static", 1000)}})
	if err != nil {
		t.Fatal(err)
	}
	first := controllerRequest(t, h, "GET", "/api/state/sync", token, nil)
	requireStatus(t, first, 200)
	full := responseMap(t, first)
	cursor := text(full, "cursor")
	data := full["data"].(map[string]any)["data"].(map[string]any)
	if data["tasks"] != nil || data["audit"] != nil || data["settings"] != nil {
		t.Fatal("heavy collections or duplicate settings in bootstrap")
	}
	unchanged := controllerRequest(t, h, "GET", "/api/state/sync?cursor="+cursor, token, nil)
	if len(unchanged.Body.Bytes()) > 500 {
		t.Fatal("unchanged state was retransmitted", unchanged.Body.Len())
	}
	row.Data["name"] = "after"
	if _, err := a.DB.SaveRecord(ctx, row); err != nil {
		t.Fatal(err)
	}
	changed := controllerRequest(t, h, "GET", "/api/state/sync?cursor="+cursor, token, nil)
	if strings.Contains(changed.Body.String(), "fixture-static") || !strings.Contains(changed.Body.String(), "after") {
		t.Fatal("static content repeated or change lost")
	}
	current := text(responseMap(t, changed), "cursor")
	if err := a.DB.DeleteRecord(ctx, "policies", "large"); err != nil {
		t.Fatal(err)
	}
	deleted := controllerRequest(t, h, "GET", "/api/state/sync?cursor="+current, token, nil)
	if !strings.Contains(deleted.Body.String(), `["data","policies","large"]`) {
		t.Fatal("missing row tombstone", deleted.Body)
	}
	member := store.User{ID: "cache-member", Username: "cache-member", Role: "user", PasswordHash: "test"}
	if err := a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, 0)
	scoped := responseMap(t, controllerRequest(t, h, "GET", "/api/state/sync?cursor="+cursor, memberToken, nil))
	if scoped["reset"] != true || strings.Contains(string(mustJSON(scoped)), "fixture-static") {
		t.Fatal("cursor leaked another account baseline")
	}
	requireStatus(t, controllerRequest(t, h, "GET", "/api/operations/tasks", memberToken, nil), 403)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/state/sync?cursor="+cursor, "", nil), 401)
	a.browserMu.Lock()
	entry := a.browserSnapshots[cursor]
	entry.at = time.Now().Add(-time.Hour)
	a.browserSnapshots[cursor] = entry
	a.browserMu.Unlock()
	expired := responseMap(t, controllerRequest(t, h, "GET", "/api/state/sync?cursor="+cursor, token, nil))
	if expired["reset"] != true {
		t.Fatal("expired baseline not reset")
	}
	legacy := responseMap(t, controllerRequest(t, h, "GET", "/api/state", token, nil))
	if legacy["user"] == nil || legacy["cursor"] != nil {
		t.Fatal("legacy endpoint changed")
	}
	t.Logf("bootstrap %d bytes; unchanged delta %d bytes", first.Body.Len(), unchanged.Body.Len())
}

func TestBrowserHistoryCorrectsOldBucketsWithoutAgentCommands(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "sample", "offline-server", "", "", "test", "uplink", 100, 1, 100, time.Now().Add(-2*time.Hour).UnixMilli(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/traffic?range=24h&interval=1m&sync=1"
	first := responseMap(t, controllerRequest(t, h, "GET", path, token, nil))
	cursor := text(first, "cursor")
	if first["reset"] != true {
		t.Fatal("missing history bootstrap")
	}
	if _, err := a.DB.DB().ExecContext(ctx, `UPDATE traffic_ledger SET raw_bytes=250,weighted_bytes=250 WHERE id='sample'`); err != nil {
		t.Fatal(err)
	}
	changed := responseMap(t, controllerRequest(t, h, "GET", path+"&cursor="+cursor, token, nil))
	patch := changed["changes"].(map[string]any)
	series, ok := patch["series"].(map[string]any)
	if !ok || len(series) != 1 {
		t.Fatal("late correction missing", patch)
	}
	for _, bucket := range series {
		if number(bucket.(map[string]any), "total") != 250/gib {
			t.Fatal("wrong corrected bucket")
		}
	}
	if _, err := a.DB.DB().ExecContext(ctx, `DELETE FROM traffic_ledger WHERE id='sample'`); err != nil {
		t.Fatal(err)
	}
	deleted := responseMap(t, controllerRequest(t, h, "GET", path+"&cursor="+text(changed, "cursor"), token, nil))
	if len(deleted["removed"].([]any)) == 0 {
		t.Fatal("removed history bucket remained cached")
	}
	tasks, err := a.DB.ListTasks(ctx, "", 100)
	if err != nil || len(tasks) != 0 {
		t.Fatal("viewing history queued Agent work", err)
	}
}

func TestBrowserXrayCacheDoesNotRepeatConfiguration(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "cache-server", Data: map[string]any{"name": "cache"}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_xrayCache", ID: "cache-server", Data: map[string]any{"config": map[string]any{"remark": strings.Repeat("config-fixture", 2000)}, "syncedAt": time.Now().UTC().Format(time.RFC3339)}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/servers/cache-server/xray-cache?sync=1"
	first := controllerRequest(t, h, "GET", path, token, nil)
	requireStatus(t, first, 200)
	next := controllerRequest(t, h, "GET", path+"&cursor="+text(responseMap(t, first), "cursor"), token, nil)
	requireStatus(t, next, 200)
	if next.Body.Len() > 500 || strings.Contains(next.Body.String(), "config-fixture") {
		t.Fatal("configuration retransmitted")
	}
	t.Logf("configuration %d bytes; unchanged delta %d bytes", first.Body.Len(), next.Body.Len())
}
