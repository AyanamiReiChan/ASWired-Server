package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

type memberTrafficAmounts struct {
	TotalBytes       float64 `json:"totalBytes"`
	UploadBytes      float64 `json:"uploadBytes"`
	DownloadBytes    float64 `json:"downloadBytes"`
	RawTotalBytes    float64 `json:"rawTotalBytes"`
	RawUploadBytes   float64 `json:"rawUploadBytes"`
	RawDownloadBytes float64 `json:"rawDownloadBytes"`
	Gap              bool    `json:"gap"`
}

func (v *memberTrafficAmounts) add(group store.MemberTrafficGroup) {
	v.TotalBytes += group.Weighted.Total
	v.UploadBytes += group.Weighted.Up
	v.DownloadBytes += group.Weighted.Down
	v.RawTotalBytes += group.Raw.Total
	v.RawUploadBytes += group.Raw.Up
	v.RawDownloadBytes += group.Raw.Down
	v.Gap = v.Gap || group.Gap
}

func (v memberTrafficAmounts) finite() bool {
	for _, value := range []float64{v.TotalBytes, v.UploadBytes, v.DownloadBytes, v.RawTotalBytes, v.RawUploadBytes, v.RawDownloadBytes} {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	return true
}

type memberTrafficRow struct {
	memberTrafficAmounts
	ID            string  `json:"id"`
	Kind          string  `json:"kind"`
	NodeID        string  `json:"nodeId"`
	InboundID     string  `json:"inboundId"`
	NodeName      string  `json:"nodeName"`
	ServerID      string  `json:"serverId"`
	ServerName    string  `json:"serverName"`
	Share         float64 `json:"share"`
	FirstSampleAt string  `json:"firstSampleAt"`
	LastSampleAt  string  `json:"lastSampleAt"`
	first, last   int64
}

func trafficTime(at int64) string { return time.UnixMilli(at).UTC().Format(time.RFC3339Nano) }

func (a *App) memberTraffic(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if len(values) > 1 || (len(values) == 1 && len(values["range"]) != 1) {
		fail(w, 400, "invalid_range", "仅支持 range=cycle、24h、7d 或 30d")
		return
	}
	rangeName := values.Get("range")
	if rangeName == "" {
		rangeName = "cycle"
	}
	if rangeName != "cycle" && rangeName != "24h" && rangeName != "7d" && rangeName != "30d" {
		fail(w, 400, "invalid_range", "仅支持 range=cycle、24h、7d 或 30d")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	member, err := a.DB.UserByID(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, 404, "not_found", "用户不存在")
		return
	}
	if err != nil {
		fail(w, 500, "storage_error", "读取用户失败")
		return
	}
	result, err := a.memberTrafficSnapshot(ctx, member.ID, rangeName, time.Now().UTC())
	if err != nil {
		fail(w, 500, "traffic_unavailable", "读取流量分布失败，请稍后重试")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, result)
}

func (a *App) memberTrafficSnapshot(ctx context.Context, memberID, rangeName string, now time.Time) (map[string]any, error) {
	subscriptions, err := a.DB.ListRecords(ctx, "subscriptions", memberID)
	if err != nil {
		return nil, err
	}
	to := now.UnixMilli()
	from := to
	windows := []map[string]any{}
	var filters []store.MemberTrafficWindow
	scope := "owner-history"
	if rangeName == "cycle" {
		scope = "current-subscription-cycles"
		filters = []store.MemberTrafficWindow{}
		for _, sub := range subscriptions {
			start := dateTime(text(sub.Data, "cycleStart"))
			if start.IsZero() {
				start = sub.CreatedAt
			}
			end := dateTime(text(sub.Data, "cycleEnd"))
			last := to
			if !end.IsZero() && end.UnixMilli() < last {
				last = end.UnixMilli()
			}
			if start.UnixMilli() >= last {
				continue
			}
			filters = append(filters, store.MemberTrafficWindow{SubscriptionID: sub.ID, Start: start.UnixMilli(), End: last})
			windows = append(windows, map[string]any{"subscriptionId": sub.ID, "subscriptionName": defaultText(sub.Data, "name", sub.ID), "from": trafficTime(start.UnixMilli()), "to": trafficTime(last)})
			if start.UnixMilli() < from {
				from = start.UnixMilli()
			}
		}
	} else {
		duration := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[rangeName]
		from = now.Add(-duration).UnixMilli()
	}
	groups, err := a.DB.MemberTrafficDistribution(ctx, memberID, from, to, filters)
	if err != nil {
		return nil, err
	}
	// These read-only metadata lookups never refresh generated nodes or execute
	// quota/availability checks. A disabled or removed node must not erase usage.
	records := map[string][]store.Record{}
	for _, collection := range []string{"servers", "inbounds", "nodes"} {
		records[collection], err = a.DB.ListRecords(ctx, collection, "")
		if err != nil {
			return nil, err
		}
	}
	servers, inbounds, nodes, subs := map[string]store.Record{}, map[string]store.Record{}, map[string]store.Record{}, map[string]store.Record{}
	for _, rec := range records["servers"] {
		servers[rec.ID] = rec
	}
	for _, rec := range records["inbounds"] {
		inbounds[rec.ID] = rec
	}
	for _, rec := range records["nodes"] {
		nodes[rec.ID] = rec
	}
	for _, rec := range subscriptions {
		subs[rec.ID] = rec
	}
	totals := memberTrafficAmounts{}
	byNode := map[string]*memberTrafficRow{}
	for _, group := range groups {
		sub := subs[group.SubscriptionID]
		server := servers[group.ServerID]
		row := memberTrafficRow{ID: "historical:" + group.ServerID, Kind: "historical", NodeName: "历史或无法细分的流量", ServerID: group.ServerID, ServerName: defaultText(server.Data, "name", group.ServerID)}
		if row.ServerName == "" {
			row.ServerName = "未知服务器"
		}
		base := text(sub.Data, "credentialEmail")
		if base != "" && strings.HasPrefix(group.Email, base+".") {
			inboundID := strings.TrimPrefix(group.Email, base+".")
			inbound, found := inbounds[inboundID]
			// Never infer identity just from an email suffix or a server having one
			// inbound. Records recreated after the first sample cannot name that
			// historical group reliably, so keep it in the server fallback group.
			if found && server.ID != "" && text(inbound.Data, "serverId") == group.ServerID && group.First >= sub.CreatedAt.UnixMilli() && group.First >= inbound.CreatedAt.UnixMilli() && group.First >= server.CreatedAt.UnixMilli() {
				row.ID = "inbound:" + group.ServerID + ":" + inboundID
				row.Kind, row.InboundID, row.NodeID = "inbound", inboundID, "inbound-"+inboundID
				row.NodeName = defaultText(inbound.Data, "name", "入站 "+inboundID)
				if node := nodes[row.NodeID]; boolean(node.Data, "managedInbound") && text(node.Data, "inboundId") == inboundID && text(node.Data, "serverId") == group.ServerID {
					row.NodeName = defaultText(node.Data, "name", row.NodeName)
				}
			}
		}
		current, exists := byNode[row.ID]
		if !exists {
			row.first, row.last = group.First, group.Last
			current = &row
			byNode[row.ID] = current
		}
		current.add(group)
		current.first = min(current.first, group.First)
		current.last = max(current.last, group.Last)
		totals.add(group)
	}
	if !totals.finite() {
		return nil, errors.New("invalid member traffic total")
	}
	rows := make([]memberTrafficRow, 0, len(byNode))
	hasUnmapped := false
	for _, row := range byNode {
		if totals.TotalBytes > 0 {
			row.Share = row.TotalBytes / totals.TotalBytes * 100
		}
		row.FirstSampleAt, row.LastSampleAt = trafficTime(row.first), trafficTime(row.last)
		hasUnmapped = hasUnmapped || row.Kind == "historical"
		rows = append(rows, *row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TotalBytes != rows[j].TotalBytes {
			return rows[i].TotalBytes > rows[j].TotalBytes
		}
		return rows[i].ID < rows[j].ID
	})
	var displayedFrom any = trafficTime(from)
	if rangeName == "cycle" && len(windows) == 0 {
		displayedFrom = nil
	}
	return map[string]any{"memberId": memberID, "range": rangeName, "generatedAt": trafficTime(to), "from": displayedFrom, "to": trafficTime(to), "endExclusive": true, "scope": scope, "windows": windows, "totals": totals, "rows": rows, "hasUnmappedTraffic": hasUnmapped}, nil
}
