package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var trafficMu sync.Mutex

func (a *App) subscriptionUsage(ctx context.Context, sub store.Record) (total, up, down float64, err error) {
	start := dateTime(text(sub.Data, "cycleStart"))
	end := dateTime(text(sub.Data, "cycleEnd"))
	if start.IsZero() {
		start = sub.CreatedAt
	}
	if end.IsZero() {
		end = time.Now().AddDate(100, 0, 0)
	}
	usage, err := a.DB.SubscriptionUsage(ctx, sub.ID, start.UnixMilli(), end.UnixMilli())
	return usage.Total, usage.Up, usage.Down, err
}

// Usage fields are derived display data. Quota decisions always read the ledger.
func setSubscriptionUsage(sub *store.Record, total, up, down float64) bool {
	used := math.Round(total/gib*10000) / 10000
	if number(sub.Data, "usedBytes") == total && number(sub.Data, "uploadBytes") == up && number(sub.Data, "downloadBytes") == down && number(sub.Data, "used") == used {
		return false
	}
	sub.Data["usedBytes"] = total
	sub.Data["uploadBytes"] = up
	sub.Data["downloadBytes"] = down
	sub.Data["used"] = used
	return true
}

type trafficOwner struct {
	SubscriptionID string
	UserID         string
	Factor         float64
}

func (a *App) accountStats(ctx context.Context, serverID string, stats map[string]any) {
	if boolean(stats, "reset") {
		slog.Warn("resetting counter snapshot rejected", "server", serverID)
		return
	}
	sampledAt := int64(number(stats, "timestamp"))
	if sampledAt <= 0 {
		sampledAt = time.Now().UnixMilli()
	}
	if sampledAt > time.Now().Add(2*time.Minute).UnixMilli() {
		return
	}
	counters, ok := stats["counters"].(map[string]any)
	if !ok {
		raw, _ := json.Marshal(stats["counters"])
		_ = json.Unmarshal(raw, &counters)
	}
	if len(counters) == 0 {
		return
	}
	trafficMu.Lock()
	defer trafficMu.Unlock()
	subscriptions, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil {
		return
	}
	inbounds, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return
	}
	server, err := a.DB.GetRecord(ctx, "servers", serverID)
	if err != nil || !nativeServer(server) {
		return
	}
	internalTransfers, err := a.trafficInternalIndex(ctx)
	if err != nil {
		return
	}
	serverFactor := number(server.Data, "multiplier")
	if serverFactor <= 0 {
		serverFactor = 1
	}
	owners := map[string]trafficOwner{}
	boundaries := map[string][]int64{}
	for _, sub := range subscriptions {
		for _, field := range []string{"cycleStart", "cycleEnd"} {
			if boundary := dateTime(text(sub.Data, field)); !boundary.IsZero() {
				boundaries[sub.ID] = append(boundaries[sub.ID], boundary.UnixMilli())
			}
		}
		plan, e := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
		if e != nil {
			continue
		}
		directionFactor := number(plan.Data, "directionFactor")
		if directionFactor != 2 {
			directionFactor = 1
		}
		base := text(sub.Data, "credentialEmail")
		owners[base] = trafficOwner{sub.ID, sub.OwnerID, serverFactor * directionFactor}
		for _, inbound := range inbounds {
			if text(inbound.Data, "serverId") != serverID {
				continue
			}
			factor := number(inbound.Data, "multiplier")
			if factor <= 0 {
				factor = serverFactor
			}
			if entry := planNodeTraffic(plan.Data, "inbound-"+inbound.ID); entry["multiplier"] != nil {
				factor = number(entry, "multiplier")
			}
			owners[base+"."+inbound.ID] = trafficOwner{sub.ID, sub.OwnerID, factor * directionFactor}
		}
	}
	tx, err := a.DB.DB().BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()

	if a.DB.Driver() == "pgx" {
		var lockedID string
		if err := tx.QueryRowContext(ctx, a.DB.Bind(`SELECT id FROM records WHERE collection=? AND id=? FOR UPDATE`), "servers", serverID).Scan(&lockedID); err != nil {
			return
		}
	} else {
		if _, err := tx.ExecContext(ctx, `UPDATE traffic_cursors SET last_value=last_value WHERE 1=0`); err != nil {
			return
		}
	}
	generation := fmt.Sprint(stats["generation"])
	if generation == "<nil>" {
		generation = "unknown"
	}
	affected := make(map[string]bool)
	for key, raw := range counters {
		parts := strings.Split(key, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" || (parts[3] != "uplink" && parts[3] != "downlink") {
			continue
		}
		currentValue, valid := counterValue(raw)
		if !valid {
			continue
		}
		var oldGeneration string
		var oldValue, oldAt int64
		err := tx.QueryRowContext(ctx, a.DB.Bind(`SELECT generation,last_value,sampled_at FROM traffic_cursors WHERE server_id=? AND counter_key=?`), serverID, key).Scan(&oldGeneration, &oldValue, &oldAt)
		first := err == sql.ErrNoRows
		if err != nil && !first {
			return
		}
		if !first && sampledAt <= oldAt {
			continue
		}
		delta := currentValue
		gap := 0
		gapReason := ""
		if !first {
			if oldGeneration != generation {
				gap = 1
				gapReason = "core_generation_changed"
			} else if currentValue < oldValue {
				gap = 1
				gapReason = "counter_decreased"
			} else {
				delta = currentValue - oldValue
			}
		}
		_, err = tx.ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_cursors(server_id,counter_key,generation,last_value,sampled_at) VALUES(?,?,?,?,?) ON CONFLICT(server_id,counter_key) DO UPDATE SET generation=excluded.generation,last_value=excluded.last_value,sampled_at=excluded.sampled_at`), serverID, key, generation, currentValue, sampledAt)
		if err != nil {
			return
		}
		owner, known := owners[parts[1]]
		if known && !first && gap == 0 {
			for _, boundary := range boundaries[owner.SubscriptionID] {
				if oldAt < boundary && sampledAt >= boundary {
					gap = 1
					gapReason = "sample_crosses_cycle_boundary"
					break
				}
			}
		}
		if !known {
			owner = trafficOwner{Factor: 1}
			if _, internal := internalTransfers[trafficPairID(serverID, parts[1])]; !internal && gap == 0 {
				gapReason = "unassigned_email"
				gap = 1
			}
		}
		weighted := float64(delta) * owner.Factor
		if math.IsNaN(weighted) || math.IsInf(weighted, 0) {
			return
		}
		if delta == 0 && gap == 0 {
			continue
		}
		_, err = tx.ExecContext(ctx, a.DB.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), newID(), serverID, owner.SubscriptionID, owner.UserID, parts[1], parts[3], delta, owner.Factor, weighted, sampledAt, gap, gapReason)
		if err != nil {
			return
		}
		affected[owner.SubscriptionID] = true
	}
	if err := tx.Commit(); err != nil {
		slog.Error("traffic commit", "server", serverID, "error", err)
		return
	}

	for _, sub := range subscriptions {
		if !affected[sub.ID] {
			continue
		}
		total, up, down, e := a.subscriptionUsage(ctx, sub)
		if e == nil && setSubscriptionUsage(&sub, total, up, down) {
			_, _ = a.DB.SaveRecord(ctx, sub)
		}
	}
	stats["timestamp"] = sampledAt
	stats["counters"] = counters
	a.evaluateBehavior(ctx, serverID, stats, owners)
}

func counterValue(value any) (int64, bool) {
	switch v := value.(type) {
	case int64:
		return v, v >= 0
	case int:
		return int64(v), v >= 0
	case uint64:
		if v <= math.MaxInt64 {
			return int64(v), true
		}
	case float64:
		if v >= 0 && v < math.MaxInt64 && math.Trunc(v) == v {
			return int64(v), true
		}
	case json.Number:
		i, e := strconv.ParseInt(string(v), 10, 64)
		return i, e == nil && i >= 0
	}
	return 0, false
}

func nextCycleEnd(plan map[string]any, start time.Time) time.Time {
	if text(plan, "reset") == "不重置" || text(plan, "reset") == "none" {
		return time.Time{}
	}
	if strings.Contains(text(plan, "reset"), "每月") {
		location, e := time.LoadLocation(defaultText(plan, "resetTimezone", "Asia/Shanghai"))
		if e != nil {
			location = time.FixedZone("Asia/Shanghai", 8*3600)
		}
		local := start.In(location)
		day := int(number(plan, "resetDay"))
		if day < 1 || day > 31 {
			day = 1
		}
		boundary := func(year int, month time.Month) time.Time {
			last := time.Date(year, month+1, 0, 0, 0, 0, 0, location).Day()
			return time.Date(year, month, min(day, last), 0, 0, 0, 0, location)
		}
		end := boundary(local.Year(), local.Month())
		if !end.After(start) {
			end = boundary(local.Year(), local.Month()+1)
		}
		return end.UTC()
	}
	days := int(number(plan, "cycleDays"))
	if days < 1 || days > 3660 {
		days = 30
	}
	return start.AddDate(0, 0, days)
}

func cyclePolicy(plan, sub map[string]any) map[string]any {
	policy := clone(plan)
	for _, key := range []string{"reset", "resetDay", "resetTimezone", "cycleDays"} {
		if value, ok := sub[key]; ok && value != nil && value != "" {
			policy[key] = value
		}
	}
	return policy
}

func cycleStamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339Nano)
}

func (a *App) expireSubscriptions(ctx context.Context) {
	subs, err := a.DB.ListRecords(ctx, "subscriptions", "")
	if err != nil {
		return
	}
	now := time.Now().UTC()
	changed := a.expireLimitPenalties(ctx, now)
	for _, sub := range subs {
		mutated := false
		plan, e := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
		if e != nil {
			continue
		}
		end := dateTime(text(sub.Data, "cycleEnd"))
		policy := cyclePolicy(plan.Data, sub.Data)
		digest := cyclePolicyDigest(policy)
		if old := text(sub.Data, "_cyclePolicyHash"); old != digest {
			// Policy edits change the next reset, never erase current usage.
			if old != "" || end.IsZero() && !nextCycleEnd(policy, now).IsZero() {
				end = nextCycleEnd(policy, now)
				sub.Data["cycleEnd"] = cycleStamp(end)
			}
			sub.Data["_cyclePolicyHash"] = digest
			mutated = true
		}
		if nextCycleEnd(policy, now).IsZero() && !end.IsZero() {
			end = time.Time{}
			sub.Data["cycleEnd"] = ""
			mutated = true
		}
		for !end.IsZero() && !now.Before(end) {
			sub.Data["cycleStart"] = end.Format(time.RFC3339Nano)
			end = nextCycleEnd(policy, end)
			sub.Data["cycleEnd"] = cycleStamp(end)
			mutated = true
		}
		state := "启用"
		if err := a.subscriptionActive(ctx, sub); err != nil {
			state = err.Error()
		} else if over, speed, e := a.quotaOutcome(ctx, sub); e == nil && over && speed > 0 {
			state = "超额限速"
		}
		if text(sub.Data, "effectiveStatus") != state {
			sub.Data["effectiveStatus"] = state
			mutated = true
		}
		// Retry failed display refreshes and rebuild after restart/restore, even
		// without new traffic. Display-only changes must not reconcile users.
		total, up, down, usageErr := a.subscriptionUsage(ctx, sub)
		usageChanged := usageErr == nil && setSubscriptionUsage(&sub, total, up, down)
		if mutated || usageChanged {
			if _, e := a.DB.SaveRecord(ctx, sub); e == nil && mutated {
				changed = true
			}
		}
	}
	if changed {
		a.reconcileUsers(ctx, store.User{ID: "system", Role: "admin", Username: "system"})
	}
}

func (a *App) trafficLedger(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := current(r)
	interval := r.URL.Query().Get("interval")
	if interval == "" {
		interval = "1d"
	}
	days, minutes := 30, 0
	rangeValue := r.URL.Query().Get("range")
	switch interval {
	case "1m":
		if r.URL.Query().Get("days") != "" {
			fail(w, 400, "invalid_range", "分钟趋势不支持按天查询")
			return
		}
		switch rangeValue {
		case "1h":
			minutes = 60
		case "6h":
			minutes = 360
		case "24h":
			minutes = 1440
		default:
			fail(w, 400, "invalid_range", "分钟趋势支持1h、6h或24h范围")
			return
		}
		days = 0
	case "1d":
		switch rangeValue {
		case "", "30d":
		case "7d":
			days = 7
		default:
			fail(w, 400, "invalid_range", "支持7d或30d范围")
			return
		}
		if raw := r.URL.Query().Get("days"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 366 {
				fail(w, 400, "invalid_range", "统计天数须为1至366")
				return
			}
			days = value
		}
	default:
		fail(w, 400, "invalid_interval", "统计间隔支持1m或1d")
		return
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -days).UnixMilli()
	if minutes > 0 {
		start = now.Truncate(time.Minute).Add(-time.Duration(minutes-1) * time.Minute).UnixMilli()
	}
	internalTransfers, err := a.trafficInternalIndex(ctx)
	if err != nil {
		fail(w, 503, "storage_error", "内部中转分类读取失败")
		return
	}
	query := `SELECT server_id,owner_id,subscription_id,email,direction,raw_bytes,weighted_bytes,sampled_at,gap FROM traffic_ledger WHERE sampled_at>=? AND sampled_at<=?`
	args := []any{start, now.UnixMilli()}
	if user.Role != "admin" {
		query += ` AND owner_id=?`
		args = append(args, user.ID)
	}
	query += ` ORDER BY sampled_at,id`
	rows, err := a.DB.DB().QueryContext(ctx, a.DB.Bind(query), args...)
	if err != nil {
		fail(w, 503, "storage_error", "流量台账读取失败")
		return
	}
	type usage struct {
		Up, Down float64
		Gap      bool
	}
	servers := map[string]*usage{}
	members := map[string]*usage{}
	internal := map[string]*usage{}
	unassigned := map[string]*usage{}
	pairRows := map[string]map[string]any{}
	buckets := map[int64]*usage{}
	gaps := 0
	sampleCount := 0
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		location = time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	for rows.Next() {
		var serverID, ownerID, subID, email, direction string
		var raw, weighted float64
		var at int64
		var gap int
		if err := rows.Scan(&serverID, &ownerID, &subID, &email, &direction, &raw, &weighted, &at, &gap); err != nil {
			rows.Close()
			fail(w, 503, "storage_error", "流量台账读取失败")
			return
		}
		sampleCount++
		if gap != 0 {
			gaps++
		}
		if servers[serverID] == nil {
			servers[serverID] = &usage{}
		}
		var pairUsage *usage
		isInternal := false
		if user.Role == "admin" && ownerID == "" && subID == "" {
			pairID := trafficPairID(serverID, email)
			if classification, exists := internalTransfers[pairID]; exists {
				isInternal = true
				if internal[pairID] == nil {
					internal[pairID] = &usage{}
					pairRows[pairID] = trafficInternalRow(classification)
					pairRows[pairID]["classificationId"] = classification.ID
					pairRows[pairID]["source"] = "Xray内部中转原始流量"
				}
				pairUsage = internal[pairID]
			} else {
				if unassigned[pairID] == nil {
					unassigned[pairID] = &usage{}
					pairRows[pairID] = map[string]any{"id": pairID, "serverId": serverID, "email": email, "name": email, "source": "Xray未归属用户流量"}
				}
				pairUsage = unassigned[pairID]
			}
		}
		if !isInternal && members[ownerID] == nil {
			members[ownerID] = &usage{}
		}
		stamp := time.UnixMilli(at).In(location)
		bucket := time.Date(stamp.Year(), stamp.Month(), stamp.Day(), 0, 0, 0, 0, location).UnixMilli()
		if minutes > 0 {
			bucket = stamp.Truncate(time.Minute).UnixMilli()
		}
		if buckets[bucket] == nil {
			buckets[bucket] = &usage{}
		}
		buckets[bucket].Gap = buckets[bucket].Gap || gap != 0
		bucketValue := raw
		if user.Role != "admin" {
			bucketValue = weighted
		}
		if direction == "uplink" {
			servers[serverID].Up += raw
			if !isInternal {
				members[ownerID].Up += weighted
			}
			if pairUsage != nil {
				pairUsage.Up += raw
			}
			buckets[bucket].Up += bucketValue
		} else {
			servers[serverID].Down += raw
			if !isInternal {
				members[ownerID].Down += weighted
			}
			if pairUsage != nil {
				pairUsage.Down += raw
			}
			buckets[bucket].Down += bucketValue
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		fail(w, 503, "storage_error", "流量台账读取失败")
		return
	}
	series := []any{}
	timestamps := []int64{}
	for at := range buckets {
		timestamps = append(timestamps, at)
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
	for _, at := range timestamps {
		v := buckets[at]
		stamp := time.UnixMilli(at).In(location)
		date := stamp.Format("2006-01-02")
		if minutes > 0 {
			date = stamp.Format("2006-01-02 15:04")
		}
		series = append(series, map[string]any{"id": date, "date": date, "at": at, "time": stamp.Format(time.RFC3339), "gap": v.Gap, "up": v.Up / gib, "down": v.Down / gib, "total": (v.Up + v.Down) / gib})
	}
	serverRows := []any{}
	serverNames := map[string]string{}
	if user.Role == "admin" {
		records, err := a.DB.ListRecords(ctx, "servers", "")
		if err != nil {
			fail(w, 503, "storage_error", "服务器读取失败")
			return
		}
		for _, rec := range records {
			serverNames[rec.ID] = text(rec.Data, "name")
			if v := servers[rec.ID]; v != nil {
				serverRows = append(serverRows, map[string]any{"id": rec.ID, "name": text(rec.Data, "name"), "up": v.Up, "down": v.Down, "used": (v.Up + v.Down) / gib, "limit": nil, "source": "Xray代理原始流量", "capacityKnown": false})
			}
		}
	}
	pairUsageRows := func(usages map[string]*usage) []any {
		result := []any{}
		ids := make([]string, 0, len(usages))
		for id := range usages {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			v := usages[id]
			row := pairRows[id]
			row["serverName"] = serverNames[text(row, "serverId")]
			if source := text(row, "sourceServerId"); source != "" {
				row["sourceServerName"] = serverNames[source]
			}
			row["up"], row["down"], row["used"], row["limit"] = v.Up, v.Down, (v.Up+v.Down)/gib, nil
			result = append(result, row)
		}
		return result
	}
	memberRows := []any{}
	ids := []string{}
	for id := range members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if id == "" && user.Role != "admin" {
			continue
		}
		v := members[id]
		name := "未归属流量"
		if id != "" {
			account, err := a.DB.UserByID(ctx, id)
			if err == nil {
				name = account.Username
			} else {
				name = "已删除成员"
			}
		}
		limit := float64(0)
		subs, _ := a.DB.ListRecords(ctx, "subscriptions", id)
		for _, sub := range subs {
			if sub.OwnerID == id {
				limit += number(sub.Data, "limit")
			}
		}
		memberRows = append(memberRows, map[string]any{"id": id, "name": name, "up": v.Up, "down": v.Down, "used": (v.Up + v.Down) / gib, "limit": limit, "source": "Xray用户加权台账"})
	}
	bucketSeconds := 86400
	if minutes > 0 {
		bucketSeconds = 60
	}
	result := map[string]any{"series": series, "servers": serverRows, "members": memberRows, "internal": pairUsageRows(internal), "unassigned": pairUsageRows(unassigned), "days": days, "interval": interval, "bucketSeconds": bucketSeconds, "from": start, "to": now.UnixMilli(), "unit": "GiB", "source": "xray-ledger", "gaps": gaps, "incomplete": gaps > 0 || sampleCount == 0, "scope": map[bool]string{true: "raw-proxy", false: "weighted-user"}[user.Role == "admin"]}
	if r.URL.Query().Get("sync") == "1" {
		for _, key := range []string{"series", "servers", "members", "internal", "unassigned"} {
			indexed := map[string]any{}
			for _, item := range result[key].([]any) {
				row := item.(map[string]any)
				indexed[text(row, "id")] = row
			}
			result[key] = indexed
		}
		// Always derive history from the controller ledger. Diffing the complete
		// projection also picks up late corrections, deletion and rolling expiry.
		a.browserResponse(w, r, result)
		return
	}
	respond(w, 200, result)
}
