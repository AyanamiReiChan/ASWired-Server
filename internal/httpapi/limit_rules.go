package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

type behaviorRule struct {
	ID              string  `json:"id"`
	Type            string  `json:"type"`
	ThresholdMbps   float64 `json:"thresholdMbps"`
	DurationSeconds float64 `json:"durationSeconds"`
	WindowSeconds   float64 `json:"windowSeconds"`
	Hits            int     `json:"hits"`
	LimitMbps       float64 `json:"limitMbps"`
	PenaltySeconds  float64 `json:"penaltySeconds"`
	Priority        int     `json:"priority"`
	Notify          bool    `json:"notify"`
	Source          string  `json:"source"`
}
type behaviorConfig struct {
	Enabled       bool           `json:"enabled"`
	MaxGapSeconds float64        `json:"maxGapSeconds"`
	Rules         []behaviorRule `json:"rules"`
}
type behaviorProgress struct {
	AboveSince int64   `json:"aboveSince"`
	Hits       []int64 `json:"hits"`
	Until      int64   `json:"until"`
	LimitMbps  float64 `json:"limitMbps"`
	Priority   int     `json:"priority"`
	Notify     bool    `json:"notify"`
	Source     string  `json:"source"`
}
type behaviorState struct {
	At          int64                       `json:"at"`
	Generation  string                      `json:"generation"`
	Counters    map[string]int64            `json:"counters"`
	Rules       map[string]behaviorProgress `json:"rules"`
	PolicyHash  string                      `json:"policyHash"`
	SampleMbps  float64                     `json:"sampleMbps"`
	SampleValid bool                        `json:"sampleValid"`
	Reason      string                      `json:"reason"`
}

var limitRuleMu sync.Mutex

func behaviorConfiguration(value any, source string) (behaviorConfig, error) {
	cfg := behaviorConfig{Enabled: true, MaxGapSeconds: 15}
	raw, err := json.Marshal(value)
	if err != nil {
		return cfg, err
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("行为限速配置格式无效")
	}
	if cfg.MaxGapSeconds < 1 || cfg.MaxGapSeconds > 300 {
		return cfg, errors.New("maxGapSeconds须为1至300秒")
	}
	if len(cfg.Rules) > 32 {
		return cfg, errors.New("每个来源最多32条行为限速规则")
	}
	seen := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID == "" || len(r.ID) > 100 || seen[r.ID] {
			return cfg, errors.New("行为规则id须非空且唯一")
		}
		seen[r.ID] = true
		for _, number := range []float64{r.ThresholdMbps, r.LimitMbps, r.PenaltySeconds, r.DurationSeconds, r.WindowSeconds} {
			if math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
				return cfg, errors.New("行为规则不能包含负数或非有限数")
			}
		}
		if r.ThresholdMbps <= 0 || r.LimitMbps <= 0 || r.PenaltySeconds < 1 || r.PenaltySeconds > 30*86400 {
			return cfg, errors.New("行为规则须有正阈值、正限速和1秒至30天处罚期")
		}
		switch r.Type {
		case "sustained":
			if r.DurationSeconds < 1 || r.DurationSeconds > 86400 {
				return cfg, errors.New("持续时间须为1至86400秒")
			}
		case "burst":
			if r.WindowSeconds < 1 || r.WindowSeconds > 3600 || r.Hits < 1 || r.Hits > 1000 {
				return cfg, errors.New("突发窗口须为1至3600秒，次数1至1000")
			}
		default:
			return cfg, errors.New("行为规则类型须为sustained或burst")
		}
		r.Source = source
		r.ID = source + "/" + r.ID
	}
	return cfg, nil
}

func validateLimitConfiguration(row map[string]any) error {
	for _, key := range []string{"speed", "connectionLimit", "ipLimit"} {
		if value, exists := row[key]; exists && value != nil && value != "" {
			n := number(row, key)
			if !finiteNumeric(value) || n < 0 || n > 1e9 || key != "speed" && math.Trunc(n) != n {
				return fmt.Errorf("%s 须为非负%s，留空继承、0 不限", key, map[bool]string{true: "整数", false: "数值"}[key != "speed"])
			}
		}
	}
	if raw, exists := row["nodeLimits"]; exists && raw != nil {
		limits, ok := raw.(map[string]any)
		if !ok || len(limits) > 500 {
			return errors.New("逐节点覆盖须为至多 500 个资源的对象")
		}
		for id, raw := range limits {
			entry, ok := raw.(map[string]any)
			if id == "" || !ok {
				return errors.New("逐节点覆盖资源或配置无效")
			}
			for key := range entry {
				if key != "speed" && key != "connectionLimit" && key != "ipLimit" {
					return errors.New("逐节点覆盖仅支持速度、连接数和 IP 上限")
				}
			}
			if err := validateLimitConfiguration(entry); err != nil {
				return err
			}
		}
	}
	if value, exists := row["behaviorLimits"]; exists && value != nil {
		if _, err := behaviorConfiguration(value, "validation"); err != nil {
			return err
		}
	}
	if mode := text(row, "quotaMode"); mode != "" && mode != "stop" && mode != "throttle" {
		return errors.New("quotaMode须为stop或throttle")
	}
	if value, exists := row["quotaSpeedMbps"]; exists && value != nil {
		n := number(row, "quotaSpeedMbps")
		if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
			return errors.New("超额降速须为正Mbps")
		}
	}
	return nil
}

func (a *App) registerLimitRules(mux *http.ServeMux) {
	for path, collection := range map[string]string{"/api/limits/effective": "_effectiveLimits", "/api/limits/events": "_limitEvents"} {
		c := collection
		mux.HandleFunc("GET "+path, a.withAdmin(func(w http.ResponseWriter, r *http.Request) {
			records, err := a.DB.ListRecords(r.Context(), c, "")
			if err != nil {
				fail(w, 503, "storage_error", "限速状态暂不可用")
				return
			}
			result := []any{}
			for i := len(records) - 1; i >= 0; i-- {
				record := records[i]
				if serverID := r.URL.Query().Get("serverId"); serverID != "" && text(record.Data, "serverId") != serverID {
					continue
				}
				row := rowOf(record, false)
				if c == "_effectiveLimits" {
					syncState, _ := a.DB.GetRecord(r.Context(), "_policySync", text(record.Data, "serverId"))
					if task, err := a.DB.GetTask(r.Context(), text(syncState.Data, "taskId")); err == nil {
						row["taskId"] = task.ID
						row["executionStatus"] = task.Status
						row["applied"] = task.Status == "success"
					}
				}
				result = append(result, row)
				if len(result) >= 1000 {
					break
				}
			}
			respond(w, 200, map[string]any{"rows": result})
		}))
	}
}

func (a *App) behaviorFor(ctx context.Context, userID, serverID string) (behaviorConfig, error) {
	member, _ := a.DB.GetRecord(ctx, "members", userID)
	if value, exists := member.Data["behaviorLimits"]; exists && value != nil {
		return behaviorConfiguration(value, "member:"+userID)
	}
	var settings map[string]any
	_ = a.DB.GetSetting(ctx, "settings", &settings)
	global := behaviorConfig{MaxGapSeconds: 15}
	var err error
	if value, exists := settings["behaviorLimits"]; exists && value != nil {
		global, err = behaviorConfiguration(value, "global")
		if err != nil {
			return global, err
		}
	}
	result := behaviorConfig{MaxGapSeconds: global.MaxGapSeconds}
	seen := map[string]bool{}
	subs, err := a.DB.ListRecords(ctx, "subscriptions", userID)
	if err != nil {
		return result, err
	}
	for _, sub := range subs {
		if a.subscriptionActive(ctx, sub) != nil {
			continue
		}
		nodes, err := a.eligibleNodes(ctx, sub)
		if err != nil {
			continue
		}
		selected := false
		for _, node := range nodes {
			if text(node.Data, "serverId") == serverID {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
		if err != nil {
			continue
		}
		cfg := global
		if value, exists := plan.Data["behaviorLimits"]; exists && value != nil {
			cfg, err = behaviorConfiguration(value, "plan:"+plan.ID)
			if err != nil {
				return result, err
			}
		}
		if !cfg.Enabled {
			continue
		}
		result.Enabled = true
		if cfg.MaxGapSeconds < result.MaxGapSeconds {
			result.MaxGapSeconds = cfg.MaxGapSeconds
		}
		for _, rule := range cfg.Rules {
			if !seen[rule.ID] {
				result.Rules = append(result.Rules, rule)
				seen[rule.ID] = true
			}
		}
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		if result.Rules[i].Priority == result.Rules[j].Priority {
			return result.Rules[i].ID < result.Rules[j].ID
		}
		return result.Rules[i].Priority < result.Rules[j].Priority
	})
	return result, nil
}

func stateData(state behaviorState) map[string]any {
	raw, _ := json.Marshal(state)
	var data map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	_ = decoder.Decode(&data)
	return data
}
func readBehaviorState(row map[string]any) behaviorState {
	var state behaviorState
	raw, _ := json.Marshal(row)
	_ = json.Unmarshal(raw, &state)
	if state.Rules == nil {
		state.Rules = map[string]behaviorProgress{}
	}
	if state.Counters == nil {
		state.Counters = map[string]int64{}
	}
	return state
}

func limitEvent(userID, serverID, ruleID, kind, reason string, progress behaviorProgress, rate float64, at int64) store.Record {
	return store.Record{Collection: "_limitEvents", ID: newID(), OwnerID: userID, Data: map[string]any{"userId": userID, "serverId": serverID, "ruleId": ruleID, "type": kind, "reason": reason, "limitMbps": progress.LimitMbps, "until": time.UnixMilli(progress.Until).UTC().Format(time.RFC3339Nano), "at": time.UnixMilli(at).UTC().Format(time.RFC3339Nano), "sampleMbps": rate, "notify": progress.Notify, "notificationStatus": map[bool]string{true: "pending", false: "disabled"}[progress.Notify], "source": progress.Source}}
}

func (a *App) evaluateBehavior(ctx context.Context, serverID string, stats map[string]any, owners map[string]trafficOwner) {
	at := int64(number(stats, "timestamp"))
	if at <= 0 {
		return
	}
	generation := fmt.Sprint(stats["generation"])
	counters, _ := stats["counters"].(map[string]any)
	if counters == nil {
		raw, _ := json.Marshal(stats["counters"])
		_ = json.Unmarshal(raw, &counters)
	}
	grouped := map[string]map[string]int64{}
	for key, value := range counters {
		parts := strings.Split(key, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" || parts[3] != "downlink" {
			continue
		}
		owner, known := owners[parts[1]]
		if !known || owner.UserID == "" {
			continue
		}
		current, valid := counterValue(value)
		if !valid {
			continue
		}
		if grouped[owner.UserID] == nil {
			grouped[owner.UserID] = map[string]int64{}
		}
		grouped[owner.UserID][key] = current
	}
	limitRuleMu.Lock()
	defer limitRuleMu.Unlock()
	changed := false
	for userID, current := range grouped {
		cfg, err := a.behaviorFor(ctx, userID, serverID)
		if err != nil {
			continue
		}
		id := serverID + "/" + userID
		record, err := a.DB.GetRecord(ctx, "_limitState", id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			continue
		}
		state := readBehaviorState(record.Data)
		if at <= state.At {
			continue
		}
		events := []store.Record{}
		hashRaw, _ := json.Marshal(cfg)
		hash := sha256.Sum256(hashRaw)
		policyHash := hex.EncodeToString(hash[:])
		if state.PolicyHash != "" && state.PolicyHash != policyHash {
			for ruleID, progress := range state.Rules {
				if progress.Until > state.At {
					events = append(events, limitEvent(userID, serverID, ruleID, "released", "configuration_changed", progress, state.SampleMbps, at))
				}
			}
			state.Rules = map[string]behaviorProgress{}
		}
		elapsed := float64(at-state.At) / 1000
		valid := state.At > 0 && generation == state.Generation && elapsed > 0 && elapsed <= cfg.MaxGapSeconds && len(current) == len(state.Counters)
		delta := float64(0)
		if valid {
			for key, value := range current {
				previous, exists := state.Counters[key]
				if !exists || value < previous {
					valid = false
					break
				}
				delta += float64(value - previous)
			}
		}
		rate := float64(0)
		reason := "observed"
		if valid {
			rate = delta * 8 / elapsed / 1e6
		} else {
			reason = "missing_baseline_generation_change_or_sample_gap"
		}
		for _, rule := range cfg.Rules {
			progress := state.Rules[rule.ID]
			if progress.Until > 0 && at >= progress.Until {
				events = append(events, limitEvent(userID, serverID, rule.ID, "released", "penalty_expired", progress, rate, at))
				progress = behaviorProgress{}
			}
			if !cfg.Enabled {
				if progress.Until > 0 {
					events = append(events, limitEvent(userID, serverID, rule.ID, "released", "rule_disabled", progress, rate, at))
				}
				state.Rules[rule.ID] = behaviorProgress{}
				continue
			}
			if progress.Until > at {
				state.Rules[rule.ID] = progress
				continue
			}
			if !valid {
				progress.AboveSince = 0
				progress.Hits = nil
				state.Rules[rule.ID] = progress
				continue
			}
			hit := rate >= rule.ThresholdMbps
			trigger := false
			if rule.Type == "sustained" {
				if !hit {
					progress.AboveSince = 0
				} else {
					if progress.AboveSince == 0 {
						progress.AboveSince = state.At
					}
					trigger = float64(at-progress.AboveSince) >= rule.DurationSeconds*1000
				}
			} else {
				cutoff := at - int64(rule.WindowSeconds*1000)
				remaining := []int64{}
				for _, sample := range progress.Hits {
					if sample > cutoff {
						remaining = append(remaining, sample)
					}
				}
				progress.Hits = remaining
				if hit {
					progress.Hits = append(progress.Hits, at)
				}
				trigger = len(progress.Hits) >= rule.Hits
			}
			if trigger {
				progress = behaviorProgress{Until: at + int64(rule.PenaltySeconds*1000), LimitMbps: rule.LimitMbps, Priority: rule.Priority, Notify: rule.Notify, Source: rule.Source}
				events = append(events, limitEvent(userID, serverID, rule.ID, "triggered", rule.Type, progress, rate, at))
			}
			state.Rules[rule.ID] = progress
		}
		state.At = at
		state.Generation = generation
		state.Counters = current
		state.PolicyHash = policyHash
		state.SampleMbps = rate
		state.SampleValid = valid
		state.Reason = reason
		record = store.Record{Collection: "_limitState", ID: id, OwnerID: userID, Version: record.Version, Data: stateData(state)}
		if _, err := a.DB.CompareAndSaveRecords(ctx, append([]store.Record{record}, events...)); err == nil && len(events) > 0 {
			a.notifyLimitEvents(ctx, events)
			changed = true
		}
	}
	if changed {
		a.reconcilePolicies(ctx, store.User{ID: "system", Role: "admin"})
	}
}

func (a *App) expireLimitPenalties(ctx context.Context, now time.Time) bool {
	limitRuleMu.Lock()
	defer limitRuleMu.Unlock()

	if events, e := a.DB.ListRecords(ctx, "_limitEvents", ""); e == nil {
		pending := []store.Record{}
		for _, event := range events {
			if text(event.Data, "notificationStatus") == "pending" {
				pending = append(pending, event)
			}
		}
		a.notifyLimitEvents(ctx, pending)
	}
	records, err := a.DB.ListRecords(ctx, "_limitState", "")
	if err != nil {
		return false
	}
	changed := false
	for _, record := range records {
		state := readBehaviorState(record.Data)
		events := []store.Record{}
		parts := strings.SplitN(record.ID, "/", 2)
		if len(parts) != 2 {
			continue
		}
		cfg, cfgErr := a.behaviorFor(ctx, record.OwnerID, parts[0])
		configurationChanged := false
		if cfgErr == nil {
			raw, _ := json.Marshal(cfg)
			hash := sha256.Sum256(raw)
			nextHash := hex.EncodeToString(hash[:])
			configurationChanged = state.PolicyHash != "" && nextHash != state.PolicyHash
			if configurationChanged {
				state.PolicyHash = nextHash
			}
		}
		for id, progress := range state.Rules {
			if progress.Until > 0 && (now.UnixMilli() >= progress.Until || configurationChanged) {
				reason := "penalty_expired"
				if configurationChanged {
					reason = "configuration_changed"
				}
				events = append(events, limitEvent(record.OwnerID, parts[0], id, "released", reason, progress, state.SampleMbps, now.UnixMilli()))
				state.Rules[id] = behaviorProgress{}
			}
		}
		if len(events) == 0 {
			continue
		}
		record.Data = stateData(state)
		if _, err := a.DB.CompareAndSaveRecords(ctx, append([]store.Record{record}, events...)); err == nil {
			a.notifyLimitEvents(ctx, events)
			changed = true
		}
	}
	return changed
}

func cappedLimit(base effectiveLimit, capMbps float64) effectiveLimit {
	if capMbps > 0 && (base.Value == 0 || base.Value > capMbps) {
		return effectiveLimit{capMbps, true}
	}
	return base
}

func (a *App) behaviorEffective(ctx context.Context, userID, serverID string, base effectiveLimit, now time.Time) (effectiveLimit, map[string]any) {
	record, _ := a.DB.GetRecord(ctx, "_limitState", serverID+"/"+userID)
	state := readBehaviorState(record.Data)
	ids := []string{}
	for id, progress := range state.Rules {
		if progress.Until > now.UnixMilli() {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left, right := state.Rules[ids[i]], state.Rules[ids[j]]
		if left.Priority == right.Priority {
			return ids[i] < ids[j]
		}
		return left.Priority < right.Priority
	})
	explanation := map[string]any{"baseMbps": base.Value, "behaviorActive": false, "sampleValid": state.SampleValid, "sampleMbps": state.SampleMbps, "sampleAt": state.At, "sampleReason": state.Reason}
	if len(ids) > 0 {
		rule := state.Rules[ids[0]]
		base = cappedLimit(base, rule.LimitMbps)
		explanation["behaviorActive"] = true
		explanation["ruleId"] = ids[0]
		explanation["behaviorLimitMbps"] = rule.LimitMbps
		explanation["until"] = time.UnixMilli(rule.Until).UTC().Format(time.RFC3339Nano)
		explanation["source"] = rule.Source
	}
	explanation["effectiveMbps"] = base.Value
	return base, explanation
}

func (a *App) quotaOutcome(ctx context.Context, sub store.Record) (bool, float64, error) {
	limit := number(sub.Data, "limit")
	if limit <= 0 {
		return false, 0, nil
	}
	used, _, _, err := a.subscriptionUsage(ctx, sub)
	if err != nil {
		return false, 0, err
	}
	if used < limit*gib {
		return false, 0, nil
	}
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil {
		return true, 0, err
	}
	return true, quotaPolicy(sub.Data, plan.Data), nil
}

func quotaPolicy(sub, plan map[string]any) float64 {
	mode := text(sub, "quotaMode")
	if mode == "" {
		mode = text(plan, "quotaMode")
	}
	speed := number(sub, "quotaSpeedMbps")
	if speed <= 0 {
		speed = number(plan, "quotaSpeedMbps")
	}
	if mode == "throttle" && speed > 0 {
		return speed
	}
	return 0
}

func (a *App) saveEffectiveLimit(ctx context.Context, serverID, userID string, data map[string]any) {
	id := serverID + "/" + userID
	old, _ := a.DB.GetRecord(ctx, "_effectiveLimits", id)
	before, _ := json.Marshal(old.Data)
	after, _ := json.Marshal(data)
	if string(before) == string(after) {
		return
	}
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_effectiveLimits", ID: id, OwnerID: userID, Version: old.Version, Data: data})
}

func (a *App) noteQuotaState(ctx context.Context, sub, plan store.Record, over bool, speed float64) {
	old, _ := a.DB.GetRecord(ctx, "_quotaState", sub.ID)
	if old.ID != "" && boolean(old.Data, "overQuota") == over && number(old.Data, "quotaSpeedMbps") == speed {
		return
	}
	data := map[string]any{"subscriptionId": sub.ID, "overQuota": over, "quotaSpeedMbps": speed}
	state := store.Record{Collection: "_quotaState", ID: sub.ID, OwnerID: sub.OwnerID, Version: old.Version, Data: data}
	records := []store.Record{state}
	if old.ID != "" || over {
		kind := "quota_released"
		reason := "quota_available"
		if over {
			kind = "quota_triggered"
			reason = "quota_stop"
			if speed > 0 {
				reason = "quota_throttle"
			}
		}
		notify := boolean(plan.Data, "quotaNotify")
		if v, exists := sub.Data["quotaNotify"]; exists {
			notify = v == true
		}
		event := limitEvent(sub.OwnerID, "", sub.ID, kind, reason, behaviorProgress{LimitMbps: speed, Notify: notify, Source: "subscription:" + sub.ID}, 0, time.Now().UnixMilli())
		records = append(records, event)
	}
	if _, err := a.DB.CompareAndSaveRecords(ctx, records); err == nil && len(records) > 1 {
		a.notifyLimitEvents(ctx, records[1:])
	}
}

func (a *App) notifyLimitEvents(ctx context.Context, events []store.Record) {
	for _, event := range events {
		if !boolean(event.Data, "notify") {
			continue
		}
		kind := "limit.trigger"
		if strings.Contains(text(event.Data, "type"), "released") {
			kind = "limit.release"
		}
		message := fmt.Sprintf("ASWired 限速事件：%s，用户 %s，规则 %s，原因 %s，速度 %.3f Mbps", text(event.Data, "type"), event.OwnerID, text(event.Data, "ruleId"), text(event.Data, "reason"), number(event.Data, "limitMbps"))
		a.emitEvent(ctx, kind, event.OwnerID, event.ID, message, event.Data)
		if _, err := a.DB.GetRecord(ctx, "_notificationEvents", hashOpaque(kind+"\n"+event.OwnerID+"\n"+event.ID)); err == nil {
			fresh, e := a.DB.GetRecord(ctx, "_limitEvents", event.ID)
			if e == nil {
				fresh.Data["notificationStatus"] = "queued"
				_, _ = a.DB.SaveRecord(ctx, fresh)
			}
		}
	}
}

func (a *App) serverSupportsThrottle(serverID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	peer := a.peers[serverID]
	return peer != nil && peer.Capabilities["shared_rate_limit"]
}
