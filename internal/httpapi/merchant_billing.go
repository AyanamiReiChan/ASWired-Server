package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var merchantMu sync.Mutex

func merchantResetClock(value string) (time.Time, error) {
	if value == "" {
		value = "00:00"
	}
	if len(value) != 5 {
		return time.Time{}, errors.New("reset time must be HH:MM")
	}
	return time.Parse("15:04", value)
}

func merchantPeriod(cfg map[string]any, at time.Time) (time.Time, time.Time) {
	loc, err := time.LoadLocation(defaultText(cfg, "timezone", "Asia/Shanghai"))
	if err != nil {
		loc = time.UTC
	}
	local := at.In(loc)
	day := int(number(cfg, "resetDay"))
	if day < 1 || day > 31 {
		day = 1
	}
	clock, _ := merchantResetClock(text(cfg, "resetTime"))
	boundary := func(month time.Month) time.Time {
		last := time.Date(local.Year(), month+1, 0, 0, 0, 0, 0, loc).Day()
		return time.Date(local.Year(), month, min(day, last), clock.Hour(), clock.Minute(), 0, 0, loc).UTC()
	}
	start := boundary(local.Month())
	if at.Before(start) {
		return boundary(local.Month() - 1), start
	}
	return start, boundary(local.Month() + 1)
}
func merchantUsed(row map[string]any) float64 {
	up, down := number(row, "uploadBytes"), number(row, "downloadBytes")
	total := up + down
	switch text(row, "direction") {
	case "upload":
		total = up
	case "download":
		total = down
	case "max":
		total = math.Max(up, down)
	}
	return math.Max(0, total+number(row, "adjustmentBytes"))
}
func merchantCycleID(cfg store.Record, start time.Time) string {
	return cfg.ID + "/" + text(cfg.Data, "revision") + "/" + start.Format("20060102T150405Z")
}
func (a *App) merchantCycle(ctx context.Context, cfg store.Record, at time.Time) (store.Record, error) {
	start, end := merchantPeriod(cfg.Data, at)
	id := merchantCycleID(cfg, start)
	row, err := a.DB.GetRecord(ctx, "_merchantCycles", id)
	if errors.Is(err, store.ErrNotFound) {
		return store.Record{Collection: "_merchantCycles", ID: id, Data: map[string]any{"serverId": cfg.ID, "revision": cfg.Data["revision"], "source": cfg.Data["source"], "direction": cfg.Data["direction"], "resetDay": cfg.Data["resetDay"], "resetTime": defaultText(cfg.Data, "resetTime", "00:00"), "timezone": cfg.Data["timezone"], "limitGB": cfg.Data["limitGB"], "start": cycleStamp(start), "end": cycleStamp(end), "uploadBytes": 0, "downloadBytes": 0, "adjustmentBytes": 0}}, nil
	}
	return row, err
}

// First samples establish a baseline. Earlier merchant usage is entered through
// an audited calibration; host lifetime counters are never called monthly use.
func (a *App) merchantSample(ctx context.Context, server store.Record, cfg store.Record) (float64, float64, time.Time, string, string, error) {
	if text(cfg.Data, "source") == "xray" {
		var up, down sql.NullFloat64
		var at sql.NullInt64
		err := a.DB.DB().QueryRowContext(ctx, a.DB.Bind(`SELECT SUM(CASE WHEN direction='downlink' THEN raw_bytes ELSE 0 END),SUM(CASE WHEN direction='uplink' THEN raw_bytes ELSE 0 END),MAX(sampled_at) FROM traffic_ledger WHERE server_id=?`), server.ID).Scan(&up, &down, &at)
		if err != nil {
			return 0, 0, time.Time{}, "", "", err
		}
		if !at.Valid {
			return 0, 0, time.Time{}, "", "", errors.New("尚无 Xray 原始流量样本")
		}
		return up.Float64, down.Float64, time.UnixMilli(at.Int64).UTC(), "xray", "", nil
	}
	obs, online, source := a.selectedObservation(ctx, server)
	if !online {
		return 0, 0, time.Time{}, "", "", errors.New("探针离线，等待新样本")
	}
	up, uok := counterValue(obs["network_tx_bytes"])
	down, dok := counterValue(obs["network_rx_bytes"])
	if !uok || !dok {
		return 0, 0, time.Time{}, "", "", errors.New("探针未提供有效累计流量")
	}
	at := time.UnixMilli(int64(number(obs, "timestamp"))).UTC()
	if source != server.ID {
		at = dateTime(text(obs, "sampled_at"))
		source += "/" + text(server.Data, "komariUUID") + "/" + hashOpaque(text(obs, "komari_base_url"))
	}
	if at.IsZero() || at.UnixMilli() <= 0 || at.After(time.Now().Add(2*time.Minute)) {
		return 0, 0, time.Time{}, "", "", errors.New("流量样本时间无效")
	}
	return float64(up), float64(down), at, source, text(obs, "boot_id"), nil
}

// Caller holds merchantMu. Cursor and cycle changes commit in a single CAS
// transaction, so retries and repeated reports cannot double count bytes.
func (a *App) collectMerchant(ctx context.Context, server store.Record, cfg store.Record) error {
	up, down, at, source, boot, err := a.merchantSample(ctx, server, cfg)
	if err != nil {
		return err
	}
	previous := dateTime(text(cfg.Data, "sampleAt"))
	if !previous.IsZero() && !at.After(previous) {
		return nil
	}
	changedSource := text(cfg.Data, "sampleSource") != source
	first := previous.IsZero() || changedSource
	if changedSource && !previous.IsZero() {
		// A probe binding change is a new accounting segment, even when the
		// configured source remains "system". Preserve the previous ledger.
		cfg.Data["revision"] = newID()
	}
	du, dd := up-number(cfg.Data, "lastUpload"), down-number(cfg.Data, "lastDownload")
	bootChanged := boot != "" && text(cfg.Data, "lastBoot") != "" && boot != text(cfg.Data, "lastBoot")
	reset := du < 0 || dd < 0 || bootChanged
	cfg.Data["lastBoot"] = boot
	if du < 0 || bootChanged {
		du = up
	}
	if dd < 0 || bootChanged {
		dd = down
	}
	cfg.Data["lastUpload"], cfg.Data["lastDownload"], cfg.Data["sampleAt"], cfg.Data["sampleSource"] = up, down, cycleStamp(at), source
	records := []store.Record{}
	if first || at.Sub(previous) > 400*24*time.Hour {
		cycle, e := a.merchantCycle(ctx, cfg, at)
		if e != nil {
			return e
		}
		cycle.Data["coverageStart"] = cycleStamp(at)
		cycle.Data["gap"] = true
		cycle.Data["gapReason"] = "从首次有效样本开始统计；更早用量请按商家数据校准"
		records = append(records, cycle)
	} else {
		total := float64(at.Sub(previous))
		cursor := previous
		_, firstEnd := merchantPeriod(cfg.Data, previous)
		crossedBoundary := firstEnd.Before(at)
		for cursor.Before(at) {
			cycle, e := a.merchantCycle(ctx, cfg, cursor)
			if e != nil {
				return e
			}
			end := dateTime(text(cycle.Data, "end"))
			until := at
			if end.Before(until) {
				until = end
			}
			fraction := float64(until.Sub(cursor)) / total
			cycle.Data["uploadBytes"] = number(cycle.Data, "uploadBytes") + du*fraction
			cycle.Data["downloadBytes"] = number(cycle.Data, "downloadBytes") + dd*fraction
			if text(cycle.Data, "coverageStart") == "" {
				cycle.Data["coverageStart"] = cycleStamp(cursor)
			}
			if reset || at.Sub(previous) > 2*time.Minute || crossedBoundary {
				cycle.Data["gap"] = true
				cycle.Data["gapReason"] = "存在计数重置、采样间隔或跨账期区间；边界按时间比例估算"
			}
			records = append(records, cycle)
			cursor = until
		}
	}
	records = append(records, cfg)
	_, err = a.DB.CompareAndSaveRecords(ctx, records)
	return err
}
func (a *App) maintainMerchantBilling(ctx context.Context) {
	merchantMu.Lock()
	defer merchantMu.Unlock()
	configs, err := a.DB.ListRecords(ctx, "_merchantBilling", "")
	if err != nil {
		return
	}
	for _, cfg := range configs {
		server, e := a.DB.GetRecord(ctx, "servers", cfg.ID)
		if e == nil {
			_ = a.collectMerchant(ctx, server, cfg)
		}
	}
}
func (a *App) merchantCurrent(ctx context.Context, id string) (map[string]any, error) {
	cfg, err := a.DB.GetRecord(ctx, "_merchantBilling", id)
	if err != nil {
		return nil, err
	}
	cycle, err := a.merchantCycle(ctx, cfg, time.Now())
	if err != nil {
		return nil, err
	}
	out := clone(cycle.Data)
	out["usedBytes"] = merchantUsed(out)
	out["sampleAt"] = cfg.Data["sampleAt"]
	out["configured"] = true
	return out, nil
}
func (a *App) registerMerchantBilling(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/servers/{id}/billing", a.withAdmin(a.merchantBillingRead))
	mux.HandleFunc("POST /api/servers/{id}/billing", a.withAdmin(a.merchantBillingSave))
	mux.HandleFunc("POST /api/servers/{id}/billing/calibrate", a.withAdmin(a.merchantBillingCalibrate))
}
func (a *App) merchantBillingRead(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), r.PathValue("id")
	cfg, err := a.DB.GetRecord(ctx, "_merchantBilling", id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, 503, "storage_error", "读取账期失败")
		return
	}
	history, err := a.DB.ListRecords(ctx, "_merchantCycles", "")
	if err != nil {
		fail(w, 503, "storage_error", "读取账本失败")
		return
	}
	rows := []map[string]any{}
	for _, row := range history {
		if text(row.Data, "serverId") == id {
			item := clone(row.Data)
			item["usedBytes"] = merchantUsed(item)
			rows = append(rows, item)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return text(rows[i], "start") > text(rows[j], "start") })
	if len(rows) > 120 {
		rows = rows[:120]
	}
	events, err := a.DB.ListRecords(ctx, "_merchantAdjustments", "")
	if err != nil {
		fail(w, 503, "storage_error", "读取校准记录失败")
		return
	}
	adjustments := []map[string]any{}
	for _, row := range events {
		if text(row.Data, "serverId") == id {
			adjustments = append(adjustments, row.Data)
		}
	}
	sort.Slice(adjustments, func(i, j int) bool { return text(adjustments[i], "at") > text(adjustments[j], "at") })
	if len(adjustments) > 100 {
		adjustments = adjustments[:100]
	}
	current, _ := a.merchantCurrent(ctx, id)
	respond(w, 200, map[string]any{"config": cfg.Data, "recordVersion": cfg.Version, "current": current, "history": rows, "adjustments": adjustments})
}
func (a *App) merchantBillingSave(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Source    string  `json:"source"`
		Direction string  `json:"direction"`
		ResetDay  int     `json:"resetDay"`
		ResetTime *string `json:"resetTime"`
		Timezone  string  `json:"timezone"`
		LimitGB   float64 `json:"limitGB"`
		Revision  string  `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Source != "system" && in.Source != "xray" {
		fail(w, 400, "invalid_source", "流量来源须为系统探针或 Xray 原始流量")
		return
	}
	if in.Direction != "upload" && in.Direction != "download" && in.Direction != "sum" && in.Direction != "max" {
		fail(w, 400, "invalid_direction", "计费方向无效")
		return
	}
	if _, err := time.LoadLocation(in.Timezone); err != nil || in.ResetDay < 1 || in.ResetDay > 31 || in.LimitGB < 0 || in.LimitGB > 1e9 {
		fail(w, 400, "invalid_cycle", "账期日期、时区或额度无效")
		return
	}
	if in.ResetTime != nil {
		if _, err := merchantResetClock(*in.ResetTime); err != nil {
			fail(w, 400, "invalid_cycle", "重置时间须为 HH:MM（00:00 至 23:59）")
			return
		}
	}
	ctx, id := r.Context(), r.PathValue("id")
	server, err := a.DB.GetRecord(ctx, "servers", id)
	if err != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	merchantMu.Lock()
	defer merchantMu.Unlock()
	old, err := a.DB.GetRecord(ctx, "_merchantBilling", id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, 503, "storage_error", "读取配置失败")
		return
	}
	if text(old.Data, "revision") != in.Revision {
		fail(w, 409, "conflict", "账期配置已改变，请刷新")
		return
	}
	if old.Version > 0 {
		// Finish sampling under the old policy before opening a new segment.
		if err = a.collectMerchant(ctx, server, old); err != nil {
			fail(w, 409, "sample_unavailable", err.Error())
			return
		}
		old, err = a.DB.GetRecord(ctx, "_merchantBilling", id)
		if err != nil {
			fail(w, 503, "storage_error", "读取配置失败")
			return
		}
	}
	resetTime := defaultText(old.Data, "resetTime", "00:00")
	if in.ResetTime != nil && *in.ResetTime != "" {
		resetTime = *in.ResetTime
	}
	data := map[string]any{"source": in.Source, "direction": in.Direction, "resetDay": in.ResetDay, "resetTime": resetTime, "timezone": in.Timezone, "limitGB": in.LimitGB, "revision": newID()}
	cfg := store.Record{Collection: "_merchantBilling", ID: id, Data: data, Version: old.Version}
	if err = a.collectMerchant(ctx, server, cfg); err != nil {
		fail(w, 409, "sample_unavailable", err.Error())
		return
	}
	a.audit(ctx, current(r), "server.billing.configure", id, data)
	respond(w, 200, map[string]any{"success": true, "message": "新统计区段已开始；旧账本保留，本月已有用量请校准"})
}
func (a *App) merchantBillingCalibrate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UsedGB     float64 `json:"usedGB"`
		Reason     string  `json:"reason"`
		Revision   string  `json:"revision"`
		SampleAt   string  `json:"sampleAt"`
		CycleStart string  `json:"cycleStart"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.UsedGB < 0 || in.UsedGB > 1e9 || len(in.Reason) < 1 || len(in.Reason) > 1000 {
		fail(w, 400, "invalid_calibration", "请填写有效商家用量和校准依据")
		return
	}
	ctx, id := r.Context(), r.PathValue("id")
	merchantMu.Lock()
	defer merchantMu.Unlock()
	cfg, err := a.DB.GetRecord(ctx, "_merchantBilling", id)
	if err != nil {
		fail(w, 409, "not_configured", "请先设置账期")
		return
	}
	if text(cfg.Data, "revision") != in.Revision {
		fail(w, 409, "conflict", "统计口径已改变，请重新核对")
		return
	}
	cycle, err := a.merchantCycle(ctx, cfg, time.Now())
	if err != nil {
		fail(w, 503, "storage_error", "读取账期失败")
		return
	}
	if text(cycle.Data, "start") != in.CycleStart {
		fail(w, 409, "cycle_changed", "账期已改变，请刷新并重新核对商家用量")
		return
	}
	// Calibrate to the latest recorded sample shown to the administrator.
	if text(cfg.Data, "sampleAt") != in.SampleAt {
		fail(w, 409, "stale_sample", "样本已更新，请刷新用量后重新校准")
		return
	}
	before := merchantUsed(cycle.Data)
	target := in.UsedGB * 1e9
	delta := target - before
	cycle.Data["adjustmentBytes"] = number(cycle.Data, "adjustmentBytes") + delta
	event := store.Record{Collection: "_merchantAdjustments", ID: newID(), OwnerID: current(r).ID, Data: map[string]any{"serverId": id, "revision": in.Revision, "cycleId": cycle.ID, "at": cycleStamp(time.Now()), "sampleAt": in.SampleAt, "actor": current(r).Username, "beforeBytes": before, "targetBytes": target, "deltaBytes": delta, "reason": in.Reason}}
	if _, err = a.DB.CompareAndSaveRecords(ctx, []store.Record{cycle, event}); err != nil {
		fail(w, 409, "conflict", "校准未提交，请刷新重试")
		return
	}
	a.audit(ctx, current(r), "server.billing.calibrate", id, event.Data)
	respond(w, 200, map[string]any{"success": true, "usedBytes": target})
}
