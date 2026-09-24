package httpapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

type limitTriggerRow struct {
	ID            string                `json:"id"`
	UserID        string                `json:"userId"`
	UserName      string                `json:"userName"`
	ServerID      string                `json:"serverId"`
	ServerName    string                `json:"serverName"`
	RuleID        string                `json:"ruleId"`
	Type          string                `json:"type"`
	Reason        string                `json:"reason"`
	Source        string                `json:"source"`
	SourceName    string                `json:"sourceName"`
	SampleMbps    float64               `json:"sampleMbps"`
	LimitMbps     float64               `json:"limitMbps"`
	At            string                `json:"at"`
	Until         string                `json:"until"`
	Status        string                `json:"status"`
	ReleasedAt    string                `json:"releasedAt,omitempty"`
	ReleaseReason string                `json:"releaseReason,omitempty"`
	Rule          *limitTriggerSnapshot `json:"rule,omitempty"`
}

// Historic events may contain arbitrary notification or subscription data.
// Expose only typed rule parameters, never the original event or its owner data.
type limitTriggerSnapshot struct {
	ID              string   `json:"id,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	Type            string   `json:"type,omitempty"`
	Source          string   `json:"source,omitempty"`
	ThresholdMbps   *float64 `json:"thresholdMbps,omitempty"`
	DurationSeconds *float64 `json:"durationSeconds,omitempty"`
	WindowSeconds   *float64 `json:"windowSeconds,omitempty"`
	Hits            *int     `json:"hits,omitempty"`
	LimitMbps       *float64 `json:"limitMbps,omitempty"`
	PenaltySeconds  *float64 `json:"penaltySeconds,omitempty"`
	Priority        *int     `json:"priority,omitempty"`
	Notify          *bool    `json:"notify,omitempty"`
	QuotaGB         *float64 `json:"quotaGB,omitempty"`
	QuotaMode       string   `json:"quotaMode,omitempty"`
}

type limitTriggerSummary struct {
	TriggerCount    int `json:"triggerCount"`
	UserCount       int `json:"userCount"`
	ActiveCount     int `json:"activeCount"`
	ActiveUserCount int `json:"activeUserCount"`
}

type limitTriggerResponse struct {
	Rows      []limitTriggerRow   `json:"rows"`
	Summary   limitTriggerSummary `json:"summary"`
	Truncated bool                `json:"truncated"`
}

func (a *App) limitTriggers(w http.ResponseWriter, r *http.Request) {
	collections := map[string][]store.Record{}
	// Batch reads stay independent of event count. Viewing history never reads
	// accounting ledgers, reevaluates rules, or reconciles Agent policies.
	for _, collection := range []string{"_limitEvents", "_limitState", "_quotaState", "members", "servers", "plans", "subscriptions"} {
		records, err := a.DB.ListRecords(r.Context(), collection, "")
		if err != nil {
			fail(w, 503, "storage_error", "限速触发记录暂不可用")
			return
		}
		collections[collection] = records
	}
	users, err := a.DB.ListUsers(r.Context())
	if err != nil {
		fail(w, 503, "storage_error", "限速触发记录暂不可用")
		return
	}
	respond(w, 200, buildLimitTriggers(collections, users, time.Now()))
}

func triggerEventTime(record store.Record) time.Time {
	if at, err := time.Parse(time.RFC3339Nano, text(record.Data, "at")); err == nil {
		return at
	}
	return record.CreatedAt
}

func triggerSnapshot(value any) *limitTriggerSnapshot {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result limitTriggerSnapshot
	if json.Unmarshal(raw, &result) != nil || result.ID == "" {
		return nil
	}
	return &result
}

func triggerIdentity(record store.Record) (string, string, string) {
	return defaultText(record.Data, "userId", record.OwnerID), text(record.Data, "serverId"), text(record.Data, "ruleId")
}

type triggerKey struct{ user, server, rule string }
type triggerCycle struct {
	triggerKey
	until int64
}

func buildLimitTriggers(collections map[string][]store.Record, users []store.User, now time.Time) limitTriggerResponse {
	result := limitTriggerResponse{Rows: []limitTriggerRow{}}
	userNames := map[string]string{}
	for _, user := range users {
		userNames[user.ID] = user.Username
	}
	for _, member := range collections["members"] {
		if name := text(member.Data, "name"); name != "" {
			userNames[member.ID] = name
		}
	}
	names := map[string]map[string]string{"member": userNames}
	for _, pair := range [][2]string{{"server", "servers"}, {"plan", "plans"}, {"subscription", "subscriptions"}} {
		names[pair[0]] = map[string]string{}
		for _, record := range collections[pair[1]] {
			names[pair[0]][record.ID] = defaultText(record.Data, "name", record.ID)
		}
	}
	nameOf := func(kind, id string) string {
		if name := names[kind][id]; name != "" {
			return name
		}
		return id
	}
	states := map[string]behaviorState{}
	stateOwners := map[string]string{}
	for _, record := range collections["_limitState"] {
		states[record.ID] = readBehaviorState(record.Data)
		stateOwners[record.ID] = record.OwnerID
	}
	quotas := map[string]store.Record{}
	for _, record := range collections["_quotaState"] {
		quotas[record.ID] = record
	}
	events := append([]store.Record(nil), collections["_limitEvents"]...)
	sort.Slice(events, func(i, j int) bool {
		a, b := triggerEventTime(events[i]), triggerEventTime(events[j])
		if !a.Equal(b) {
			return a.After(b)
		}
		if !events[i].CreatedAt.Equal(events[j].CreatedAt) {
			return events[i].CreatedAt.After(events[j].CreatedAt)
		}
		return events[i].ID > events[j].ID
	})
	releases := map[triggerCycle]store.Record{}
	quotaNext := map[triggerKey]store.Record{}
	seenUsers, activeUsers := map[string]bool{}, map[string]bool{}
	for _, event := range events {
		kind := text(event.Data, "type")
		if kind != "triggered" && kind != "released" && kind != "quota_triggered" && kind != "quota_released" {
			continue
		}
		userID, serverID, ruleID := triggerIdentity(event)
		key := triggerKey{userID, serverID, ruleID}
		at := triggerEventTime(event)
		until, _ := time.Parse(time.RFC3339Nano, text(event.Data, "until"))
		cycle := triggerCycle{key, until.UnixMilli()}
		if kind == "released" {
			if !at.After(now) && !until.IsZero() {
				releases[cycle] = event
			}
			continue
		}
		if kind == "quota_released" {
			if !at.After(now) {
				quotaNext[key] = event
			}
			continue
		}
		if len(result.Rows) == 1000 {
			result.Truncated = true
			break
		}
		row := limitTriggerRow{
			ID: event.ID, UserID: userID, UserName: nameOf("member", userID),
			ServerID: serverID, ServerName: nameOf("server", serverID), RuleID: ruleID,
			Type: kind, Reason: text(event.Data, "reason"), Source: text(event.Data, "source"),
			SampleMbps: number(event.Data, "sampleMbps"), LimitMbps: number(event.Data, "limitMbps"),
			At: at.UTC().Format(time.RFC3339Nano), Status: "unknown", Rule: triggerSnapshot(event.Data["rule"]),
		}
		if row.Source == "global" {
			row.SourceName = "全局规则"
		} else if scope, id, ok := strings.Cut(row.Source, ":"); ok {
			row.SourceName = nameOf(scope, id)
		} else {
			row.SourceName = row.Source
		}
		setRelease := func(release store.Record) {
			row.Status = "released"
			row.ReleasedAt = triggerEventTime(release).UTC().Format(time.RFC3339Nano)
			row.ReleaseReason = text(release.Data, "reason")
		}
		if kind == "triggered" {
			if !until.IsZero() && until.UnixMilli() > 0 {
				row.Until = until.UTC().Format(time.RFC3339Nano)
			}
			if !at.After(now) {
				state := states[serverID+"/"+userID]
				progress := state.Rules[ruleID]
				if release, ok := releases[cycle]; ok && !triggerEventTime(release).Before(at) {
					setRelease(release)
				} else if until.UnixMilli() > 0 && !until.After(now) {
					row.Status = "expired"
				} else if userID != "" && serverID != "" && ruleID != "" && stateOwners[serverID+"/"+userID] == userID && until.After(now) && progress.Until == until.UnixMilli() && progress.LimitMbps == row.LimitMbps && state.At >= at.UnixMilli() {
					row.Status = "active"
				}
			}
		} else if !at.After(now) {
			// A quota can trigger repeatedly at the same speed. Only its latest
			// uninterrupted cycle may match the present quota state.
			next, hasNext := quotaNext[key]
			quota, exists := quotas[ruleID]
			if hasNext && text(next.Data, "type") == "quota_released" {
				setRelease(next)
			} else if userID != "" && ruleID != "" && !hasNext && exists && quota.OwnerID == userID && boolean(quota.Data, "overQuota") && number(quota.Data, "quotaSpeedMbps") == row.LimitMbps && !quota.UpdatedAt.Before(at) && !quota.UpdatedAt.After(event.CreatedAt) {
				row.Status = "active"
			}
			quotaNext[key] = event
		}
		result.Rows = append(result.Rows, row)
		if userID != "" {
			seenUsers[userID] = true
		}
		if row.Status == "active" {
			result.Summary.ActiveCount++
			activeUsers[userID] = true
		}
	}
	result.Summary.TriggerCount = len(result.Rows)
	result.Summary.UserCount = len(seenUsers)
	result.Summary.ActiveUserCount = len(activeUsers)
	return result
}
