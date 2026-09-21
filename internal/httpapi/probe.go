package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/coder/websocket"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var metricNames = map[string]string{"cpu_pct": "cpu_percent", "mem_used": "memory_used", "mem_total": "memory_total", "disk_used": "disk_used", "disk_total": "disk_total", "upload_speed": "network_tx_per_second", "download_speed": "network_rx_per_second", "cumulative_up": "network_tx_bytes", "cumulative_down": "network_rx_bytes"}

func (a *App) publicAppearance(w http.ResponseWriter, r *http.Request) {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	respond(w, 200, map[string]any{"customCSS": text(settings, "customCSS"), "probeLoginOrigin": defaultText(settings, "probeLoginOrigin", a.Config.PublicURL)})
}

func (a *App) selectedObservation(ctx context.Context, server store.Record) (map[string]any, bool, string) {
	metricID := "komari:" + server.ID
	obs, err := a.DB.GetRecord(ctx, "_komariObservations", server.ID)
	if err != nil || text(server.Data, "komariUUID") == "" || text(obs.Data, "komari_uuid") != text(server.Data, "komariUUID") {
		return nil, false, metricID
	}
	var settings map[string]any
	_ = a.DB.GetSetting(ctx, "settings", &settings)
	if text(obs.Data, "komari_base_url") != komariBaseURL(settings) || komariBaseURL(settings) == "" {
		return nil, false, metricID
	}
	sampled, err := time.Parse(time.RFC3339Nano, text(obs.Data, "sampled_at"))
	age := time.Since(sampled)
	return obs.Data, err == nil && age >= -time.Minute && age < 90*time.Second && boolean(obs.Data, "online"), metricID
}
func (a *App) probeAccess(r *http.Request) (map[string]any, bool) {
	var settings map[string]any
	_ = a.DB.GetSetting(r.Context(), "settings", &settings)
	if !boolean(settings, "probePublicEnabled") {
		return settings, false
	}
	if key := text(settings, "probeAccessKey"); key != "" && !constant(key, r.Header.Get("X-MMwx-Probe-Token")) {
		return settings, false
	}
	return settings, true
}
func (a *App) publicServers(ctx context.Context, settings map[string]any) ([]store.Record, error) {
	records, e := a.DB.ListRecords(ctx, "servers", "")
	if e != nil {
		return nil, e
	}
	allowed := map[string]bool{}
	for _, id := range stringList(settings["publicServerIds"]) {
		allowed[id] = true
	}
	out := []store.Record{}
	for _, rec := range records {
		if allowed[rec.ID] || boolean(rec.Data, "public") {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (a *App) projection(ctx context.Context, settings map[string]any) (map[string]any, error) {
	records, e := a.publicServers(ctx, settings)
	if e != nil {
		return nil, e
	}
	rows := []any{}
	for _, server := range records {
		observation, online, _ := a.selectedObservation(ctx, server)
		row := map[string]any{"online": online, "region": server.Data["region"], "traffic_limit": number(server.Data, "limit") * 1024 * 1024 * 1024}
		if v, exists := settings["showName"]; !exists || v == true {
			row["name"] = text(server.Data, "name")
		}
		if boolean(settings, "showGlobe") {
			lat, latOK := server.Data["latitude"]
			lon, lonOK := server.Data["longitude"]
			if latOK && lonOK && finiteNumeric(lat) && finiteNumeric(lon) && number(server.Data, "latitude") >= -90 && number(server.Data, "latitude") <= 90 && number(server.Data, "longitude") >= -180 && number(server.Data, "longitude") <= 180 {
				row["latitude"] = lat
				row["longitude"] = lon
			}
		}
		if boolean(settings, "showAssets") {
			for _, key := range []string{"provider_name", "provider_url", "expires_at", "renewal_price", "renewal_currency", "renewal_cycle"} {
				if v, ok := server.Data[key]; ok {
					row[key] = v
				}
			}
		}
		if observation != nil {
			if strings.TrimSpace(text(row, "region")) == "" {
				row["region"] = text(observation, "region")
			}
			for public, source := range metricNames {
				if (public == "cpu_pct" && settings["showCPU"] == false) || ((public == "mem_used" || public == "mem_total") && settings["showMemory"] == false) || ((public == "upload_speed" || public == "download_speed" || public == "cumulative_up" || public == "cumulative_down") && settings["showTraffic"] == false) {
					continue
				}
				if v, ok := observation[source]; ok {
					row[public] = v
				}
			}
			for _, key := range []string{"uptime", "os", "kernel", "arch"} {
				if v, ok := observation[key]; ok {
					row[key] = v
				}
			}
		}
		rows = append(rows, row)
	}
	return map[string]any{"enabled": true, "title": defaultText(settings, "workspace", "ASWired"), "show_name": settings["showName"] != false, "show_globe": boolean(settings, "showGlobe"), "show_assets": boolean(settings, "showAssets"), "appearance": map[string]any{"color_mode": "dark"}, "servers": rows}, nil
}
func (a *App) probeServers(w http.ResponseWriter, r *http.Request) {
	settings, allowed := a.probeAccess(r)
	if !allowed {
		if boolean(settings, "probePublicEnabled") {
			fail(w, 404, "not_found", "探针接口未开放")
		} else {
			respond(w, 200, map[string]bool{"enabled": false})
		}
		return
	}
	data, e := a.projection(r.Context(), settings)
	if e != nil {
		fail(w, 503, "probe_unavailable", "观测数据暂不可用")
		return
	}
	respond(w, 200, data)
}
func (a *App) probeSeries(w http.ResponseWriter, r *http.Request) {
	settings, allowed := a.probeAccess(r)
	if !allowed {
		fail(w, 404, "not_found", "探针接口未开放")
		return
	}
	servers, e := a.publicServers(r.Context(), settings)
	if e != nil {
		fail(w, 503, "probe_unavailable", "观测数据暂不可用")
		return
	}
	index, e := strconv.Atoi(r.URL.Query().Get("server"))
	if e != nil || index < 0 || index >= len(servers) {
		fail(w, 400, "invalid_server", "公开服务器下标无效")
		return
	}
	rangeValue := r.URL.Query().Get("range")
	hours, bucket := 1, 300
	switch rangeValue {
	case "", "1h":
	case "6h":
		hours, bucket = 6, 600
	case "24h":
		hours, bucket = 24, 1800
	default:
		fail(w, 400, "invalid_range", "支持1h、6h、24h")
		return
	}
	metric := r.URL.Query().Get("metric")
	if metric != "" && metric != "system" && metric != "network" {
		fail(w, 400, "invalid_metric", "指标须为system或network")
		return
	}
	names := metricNames
	if metric == "network" {
		if settings["showNetworkQuality"] != true {
			respond(w, 200, map[string]any{"series": map[string]any{}, "reason": "网络质量历史未公开"})
			return
		}
		names = map[string]string{"latency_ms": "average_ms", "failure_percent": "failure_percent", "jitter_ms": "jitter_ms"}
	}
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "0"
	}
	if metric == "network" {
		if index, err := strconv.Atoi(target); err != nil || index < 0 {
			fail(w, 400, "invalid_target", "网络监测序号无效")
			return
		}
	}
	metrics, method, e := a.komariHistory(r.Context(), servers[index], hours, metric == "network", target)
	if e != nil {
		fail(w, 503, "probe_unavailable", "历史读取失败")
		return
	}
	type accumulator struct {
		sum   float64
		count int
	}
	buckets := map[string]map[int64]*accumulator{}
	for _, m := range metrics {
		if metric == "network" {
			if text(m.Values, "sampleId") != servers[index].ID+"/"+target {
				continue
			}
			method = text(m.Values, "method")
		}
		t := m.RecordedAt.Unix() / int64(bucket) * int64(bucket)
		for public, source := range names {
			if (public == "cpu_pct" && settings["showCPU"] == false) || ((public == "mem_used" || public == "mem_total") && settings["showMemory"] == false) || ((public == "upload_speed" || public == "download_speed" || public == "cumulative_up" || public == "cumulative_down") && settings["showTraffic"] == false) {
				continue
			}
			if _, ok := m.Values[source]; !ok {
				continue
			}
			if buckets[public] == nil {
				buckets[public] = map[int64]*accumulator{}
			}
			v := buckets[public][t]
			if v == nil {
				v = &accumulator{}
				buckets[public][t] = v
			}
			v.sum += number(m.Values, source)
			v.count++
		}
	}
	series := map[string]any{}
	for key, points := range buckets {
		times := []int64{}
		for t := range points {
			times = append(times, t)
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		out := []any{}
		for _, t := range times {
			v := points[t]
			out = append(out, map[string]any{"t": t, "value": v.sum / float64(v.count)})
		}
		series[key] = out
	}
	respond(w, 200, map[string]any{"success": true, "bucket_sec": bucket, "generated_at": time.Now().UTC(), "series": series, "method": method})
}
func (a *App) probeWS(w http.ResponseWriter, r *http.Request) {
	a.stateMu.RLock()
	_, allowed := a.probeAccess(r)
	a.stateMu.RUnlock()
	if !allowed {
		fail(w, 404, "not_found", "探针接口未开放")
		return
	}
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: a.Config.AllowedOrigins})
	if e != nil {
		return
	}
	defer conn.CloseNow()
	if !a.trackSocket(conn) {
		return
	}
	defer a.forgetSocket(conn)
	ctx := conn.CloseRead(r.Context())
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		a.stateMu.RLock()
		settings, ok := a.probeAccess(r)
		if !ok {
			a.stateMu.RUnlock()
			return
		}
		data, e := a.projection(ctx, settings)
		a.stateMu.RUnlock()
		if e != nil {
			return
		}
		raw, _ := json.Marshal(data)
		writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		e = conn.Write(writeCtx, websocket.MessageText, raw)
		cancel()
		if e != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (a *App) traffic(w http.ResponseWriter, r *http.Request) { a.trafficLedger(w, r) }

func finiteNumeric(value any) bool {
	var n float64
	switch value := value.(type) {
	case float64:
		n = value
	case int:
		n = float64(value)
	case int64:
		n = float64(value)
	case json.Number:
		v, e := value.Float64()
		if e != nil {
			return false
		}
		n = v
	default:
		return false
	}
	return !math.IsNaN(n) && !math.IsInf(n, 0)
}
