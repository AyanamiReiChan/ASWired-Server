package httpapi

import (
	"errors"
	"net/http"
	"sort"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// The catalog describes configured sources, not the Cartesian product of users
// and servers. In particular it never evaluates subscription usage or creates
// runtime policy state as a side effect of viewing the page.
type limitRuleGroup struct {
	ID            string           `json:"id"`
	Scope         string           `json:"scope"`
	Source        string           `json:"source"`
	SourceID      string           `json:"sourceId"`
	Name          string           `json:"name"`
	Mode          string           `json:"mode"`
	Enabled       bool             `json:"enabled"`
	MaxGapSeconds float64          `json:"maxGapSeconds"`
	Rules         []map[string]any `json:"rules"`
	Error         string           `json:"error,omitempty"`
}

func limitCatalogBehavior(scope, id, name string, value any) limitRuleGroup {
	source := scope
	if id != "" {
		source += ":" + id
	}
	group := limitRuleGroup{ID: source, Scope: scope, Source: source, SourceID: id, Name: name, Mode: "inherited", Rules: []map[string]any{}}
	if value == nil && scope != "global" {
		return group
	}
	group.Mode = "custom"
	if value == nil {
		value = defaultBehaviorLimits()
		group.Mode = "builtin"
	}
	cfg, err := behaviorConfiguration(value, source)
	if err != nil {
		group.Mode, group.Error = "invalid", err.Error()
		return group
	}
	group.Enabled, group.MaxGapSeconds = cfg.Enabled, cfg.MaxGapSeconds
	if !cfg.Enabled {
		group.Mode = "disabled"
	} else if len(cfg.Rules) == 0 {
		group.Mode = "empty"
	}
	for _, rule := range cfg.Rules {
		group.Rules = append(group.Rules, map[string]any{
			"id": rule.ID, "kind": "behavior", "enabled": cfg.Enabled,
			"type": rule.Type, "thresholdMbps": rule.ThresholdMbps,
			"durationSeconds": rule.DurationSeconds, "windowSeconds": rule.WindowSeconds,
			"hits": rule.Hits, "limitMbps": rule.LimitMbps, "penaltySeconds": rule.PenaltySeconds,
			"priority": rule.Priority, "notify": rule.Notify, "source": rule.Source,
		})
	}
	return group
}

func limitCatalogSpeeds(group *limitRuleGroup, data map[string]any, resources map[string]string) {
	if speed := limitValue(data, "speed"); speed.Set {
		group.Rules = append(group.Rules, map[string]any{"id": group.ID + "/speed", "kind": "speed", "enabled": true, "limitMbps": speed.Value})
	}
	limits, _ := data["nodeLimits"].(map[string]any)
	ids := make([]string, 0, len(limits))
	for id := range limits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		entry, _ := limits[id].(map[string]any)
		if speed := limitValue(entry, "speed"); speed.Set {
			name := resources[id]
			if name == "" {
				name = id
			}
			group.Rules = append(group.Rules, map[string]any{"id": group.ID + "/speed/" + id, "kind": "speed", "enabled": true, "limitMbps": speed.Value, "resourceId": id, "resourceName": name})
		}
	}
}

func limitCatalogQuota(group *limitRuleGroup, data, plan map[string]any) {
	// Absent subscription settings inherit their plan and are represented once
	// in that plan's group.
	if text(data, "quotaMode") == "" && data["quotaSpeedMbps"] == nil {
		return
	}
	speed := quotaPolicy(data, plan)
	mode := "stop"
	if speed > 0 {
		mode = "throttle"
	}
	rule := map[string]any{"id": group.ID + "/quota", "kind": "quota", "enabled": true, "quotaMode": mode, "limitMbps": speed}
	if group.Scope == "subscription" {
		rule["quotaGB"] = number(data, "limit")
		// A subscription without a positive quota never triggers quotaOutcome.
		rule["enabled"] = number(data, "limit") > 0
	}
	group.Rules = append(group.Rules, rule)
}

func (a *App) limitRulesCatalog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var settings map[string]any
	if err := a.DB.GetSetting(ctx, "settings", &settings); err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, 503, "storage_error", "限速规则暂不可用")
		return
	}
	collections := map[string][]store.Record{}
	for _, collection := range []string{"plans", "members", "subscriptions", "nodes", "servers"} {
		records, err := a.DB.ListRecords(ctx, collection, "")
		if err != nil {
			fail(w, 503, "storage_error", "限速规则暂不可用")
			return
		}
		collections[collection] = records
	}
	users, err := a.DB.ListUsers(ctx)
	if err != nil {
		fail(w, 503, "storage_error", "限速规则暂不可用")
		return
	}
	resources := map[string]string{}
	for _, collection := range []string{"servers", "nodes"} {
		for _, record := range collections[collection] {
			resources[record.ID] = defaultText(record.Data, "name", record.ID)
		}
	}
	groups := []limitRuleGroup{limitCatalogBehavior("global", "", "全局规则", settings["behaviorLimits"])}
	inheritance := map[string]int{"planInherited": 0, "planOverrides": 0, "memberInherited": 0, "memberOverrides": 0}
	plans := map[string]store.Record{}
	for _, plan := range collections["plans"] {
		plans[plan.ID] = plan
		group := limitCatalogBehavior("plan", plan.ID, defaultText(plan.Data, "name", plan.ID), plan.Data["behaviorLimits"])
		key := "planInherited"
		if group.Mode != "inherited" {
			key = "planOverrides"
		}
		inheritance[key]++
		limitCatalogSpeeds(&group, plan.Data, resources)
		limitCatalogQuota(&group, plan.Data, nil)
		if group.Mode != "inherited" || len(group.Rules) > 0 {
			groups = append(groups, group)
		}
	}
	profiles := map[string]store.Record{}
	for _, record := range collections["members"] {
		profiles[record.ID] = record
	}
	for _, user := range users {
		data := profiles[user.ID].Data
		group := limitCatalogBehavior("member", user.ID, defaultText(data, "name", user.Username), data["behaviorLimits"])
		key := "memberInherited"
		if group.Mode != "inherited" {
			key = "memberOverrides"
		}
		inheritance[key]++
		limitCatalogSpeeds(&group, data, resources)
		if group.Mode != "inherited" || len(group.Rules) > 0 {
			groups = append(groups, group)
		}
	}
	for _, sub := range collections["subscriptions"] {
		group := limitCatalogBehavior("subscription", sub.ID, defaultText(sub.Data, "name", sub.ID), nil)
		limitCatalogQuota(&group, sub.Data, plans[text(sub.Data, "planId")].Data)
		if len(group.Rules) > 0 {
			groups = append(groups, group)
		}
	}
	// Keep source sections stable across refreshes, including identical names.
	scopeOrder := map[string]int{"global": 0, "plan": 1, "member": 2, "subscription": 3}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Scope != groups[j].Scope {
			return scopeOrder[groups[i].Scope] < scopeOrder[groups[j].Scope]
		}
		if groups[i].Name != groups[j].Name {
			return groups[i].Name < groups[j].Name
		}
		return groups[i].ID < groups[j].ID
	})
	respond(w, 200, map[string]any{"groups": groups, "inheritance": inheritance})
}
