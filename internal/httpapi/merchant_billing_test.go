package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"testing"
	"time"
)

func TestMerchantCalendarAndDirection(t *testing.T) {
	at := dateTime("2028-03-01T00:00:00+08:00")
	start, end := merchantPeriod(map[string]any{"resetDay": 31, "timezone": "Asia/Shanghai"}, at)
	if cycleStamp(start) != "2028-02-28T16:00:00Z" || cycleStamp(end) != "2028-03-30T16:00:00Z" {
		t.Fatal(start, end)
	}
	for mode, want := range map[string]float64{"upload": 120, "download": 220, "sum": 320, "max": 220} {
		if got := merchantUsed(map[string]any{"uploadBytes": 100, "downloadBytes": 200, "adjustmentBytes": 20, "direction": mode}); got != want {
			t.Fatal(mode, got)
		}
	}
}

func TestMerchantResetMinuteBoundary(t *testing.T) {
	cfg := map[string]any{"resetDay": 20, "resetTime": "13:06", "timezone": "Asia/Shanghai"}
	for _, tc := range []struct{ at, start, end string }{
		{"2026-10-20T13:05:59+08:00", "2026-09-20T05:06:00Z", "2026-10-20T05:06:00Z"},
		{"2026-10-20T13:06:00+08:00", "2026-10-20T05:06:00Z", "2026-11-20T05:06:00Z"},
	} {
		start, end := merchantPeriod(cfg, dateTime(tc.at))
		if cycleStamp(start) != tc.start || cycleStamp(end) != tc.end {
			t.Fatal(tc, start, end)
		}
	}
	for _, invalid := range []string{"24:00", "12:60", "1:00", "13:06:00"} {
		if _, err := merchantResetClock(invalid); err == nil {
			t.Fatal("accepted", invalid)
		}
	}
}

func TestMerchantXrayUsesRawBytesFromHostPerspective(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	for i, direction := range []string{"uplink", "downlink"} {
		_, err := a.DB.DB().ExecContext(ctx, `INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, direction, "server", "sub", "user", "email", direction, (i+1)*100, 5, (i+1)*500, time.Now().UnixMilli(), 0, "")
		if err != nil {
			t.Fatal(err)
		}
	}
	up, down, _, _, _, err := a.merchantSample(ctx, store.Record{ID: "server"}, store.Record{Data: map[string]any{"source": "xray"}})
	if err != nil || up != 200 || down != 100 {
		t.Fatal("weighted or reversed merchant usage", up, down, err)
	}
}

func TestMerchantSamplingDedupResetAndCalibration(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	server, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "merchant", Data: map[string]any{"name": "Merchant", "connection": "WebSocket", "komariUUID": "node"}})
	if err != nil {
		t.Fatal(err)
	}
	a.peers[server.ID] = &peer{LastSeen: time.Now()}
	now := time.Now().Add(-20 * time.Second).UTC()
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": "http://komari.test"})
	observation := store.Record{Collection: "_komariObservations", ID: server.ID}
	sample := func(up, down int64, at time.Time) {
		t.Helper()
		observation.Data = map[string]any{"komari_uuid": "node", "komari_base_url": "http://komari.test", "online": true, "sampled_at": at.Format(time.RFC3339Nano), "network_tx_bytes": up, "network_rx_bytes": down}
		var e error
		observation, e = a.DB.SaveRecord(ctx, observation)
		if e != nil {
			t.Fatal(e)
		}
	}
	sample(1000, 2000, now)
	cfg := store.Record{Collection: "_merchantBilling", ID: server.ID, Data: map[string]any{"source": "system", "direction": "sum", "resetDay": 1, "timezone": "Asia/Shanghai", "limitGB": 2000, "revision": "one"}}
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, _ = a.DB.GetRecord(ctx, "_merchantBilling", server.ID)
	current, _ := a.merchantCurrent(ctx, server.ID)
	if number(current, "usedBytes") != 0 {
		t.Fatal("host lifetime counted as current month")
	}
	sample(1300, 2500, now.Add(5*time.Second))
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, _ = a.DB.GetRecord(ctx, "_merchantBilling", server.ID)
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	current, _ = a.merchantCurrent(ctx, server.ID)
	if number(current, "usedBytes") != 800 {
		t.Fatal("duplicate or wrong delta", current)
	}
	sample(100, 200, now.Add(10*time.Second))
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	current, _ = a.merchantCurrent(ctx, server.ID)
	if number(current, "usedBytes") != 1100 {
		t.Fatal("reset lost previous usage", current)
	}
	body := map[string]any{"usedGB": 2, "reason": "merchant panel", "revision": "one", "sampleAt": current["sampleAt"], "cycleStart": current["start"]}
	body["cycleStart"] = "previous-cycle"
	requireStatus(t, controllerRequest(t, h, "POST", "/api/servers/merchant/billing/calibrate", token, body), 409)
	body["cycleStart"] = current["start"]
	requireStatus(t, controllerRequest(t, h, "POST", "/api/servers/merchant/billing/calibrate", token, body), 200)
	current, _ = a.merchantCurrent(ctx, server.ID)
	if number(current, "usedBytes") != 2e9 {
		t.Fatal("calibration incorrect", current)
	}
	events, _ := a.DB.ListRecords(ctx, "_merchantAdjustments", "")
	if len(events) != 1 || number(events[0].Data, "beforeBytes") != 1100 {
		t.Fatal("calibration not audited")
	}
	cfg, _ = a.DB.GetRecord(ctx, "_merchantBilling", server.ID)
	sample(150, 250, now.Add(15*time.Second))
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	current, _ = a.merchantCurrent(ctx, server.ID)
	if number(current, "usedBytes") != 2e9+100 {
		t.Fatal("calibration swallowed subsequent traffic", current)
	}
	body["revision"] = "stale"
	requireStatus(t, controllerRequest(t, h, "POST", "/api/servers/merchant/billing/calibrate", token, body), 409)
	member := store.User{ID: "member", Username: "member", Role: "user", TokenVersion: 1, PasswordHash: "fixture"}
	if err = a.DB.CreateUser(ctx, member); err != nil {
		t.Fatal(err)
	}
	memberToken, _ := a.Signer.Issue(member.ID, member.TokenVersion)
	requireStatus(t, controllerRequest(t, h, "GET", "/api/servers/merchant/billing", memberToken, nil), 403)
}

func TestMerchantCrossBoundaryPreservesBytesAndOldPolicy(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	server := store.Record{ID: "server", Data: map[string]any{"komariUUID": "node"}}
	now := time.Now().UTC()
	at := now.Truncate(24 * time.Hour).Add(-10 * time.Second)
	_ = a.DB.SetSetting(ctx, "settings", map[string]any{"probeBaseUrl": "http://komari.test"})
	cfg := store.Record{Collection: "_merchantBilling", ID: "server", Data: map[string]any{"source": "system", "direction": "sum", "resetDay": now.Day(), "timezone": "UTC", "revision": "old", "lastUpload": 100, "lastDownload": 100, "sampleAt": cycleStamp(at), "sampleSource": "komari:server/node/" + hashOpaque("http://komari.test")}}
	cfg, err := a.DB.SaveRecord(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.peers["server"] = &peer{LastSeen: time.Now()}
	_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_komariObservations", ID: "server", Data: map[string]any{"komari_uuid": "node", "komari_base_url": "http://komari.test", "online": true, "sampled_at": now.Format(time.RFC3339Nano), "network_tx_bytes": 300, "network_rx_bytes": 300}})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	rows, _ := a.DB.ListRecords(ctx, "_merchantCycles", "")
	if len(rows) != 2 {
		t.Fatal("missing monthly boundary", rows)
	}
	total := float64(0)
	for _, row := range rows {
		total += merchantUsed(row.Data)
		if merchantUsed(row.Data) <= 0 || !boolean(row.Data, "gap") {
			t.Fatal("cross-boundary allocation wrong", row.Data)
		}
	}
	if total < 399.999 || total > 400.001 {
		t.Fatal("cross-boundary bytes lost", total)
	}
	cfg, _ = a.DB.GetRecord(ctx, "_merchantBilling", "server")
	cfg.Data["revision"] = "new"
	delete(cfg.Data, "sampleAt")
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		t.Fatal(err)
	}
	rows, _ = a.DB.ListRecords(ctx, "_merchantCycles", "")
	if len(rows) != 3 {
		t.Fatal("old policy erased", rows)
	}
}
