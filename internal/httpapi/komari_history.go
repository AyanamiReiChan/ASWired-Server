package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var komariMetricNames = map[string]string{"cpu": "cpu_percent", "ram": "memory_used", "ram_total": "memory_total", "disk": "disk_used", "disk_total": "disk_total", "net_in": "network_rx_per_second", "net_out": "network_tx_per_second", "net_total_up": "network_tx_bytes", "net_total_down": "network_rx_bytes", "uptime": "uptime", "load": "load1", "load5": "load5", "load15": "load15"}

func (a *App) komariRPC(ctx context.Context, settings map[string]any, method string, params map[string]any, out any) error {
	base := komariBaseURL(settings)
	if base == "" {
		return errors.New("请先配置 Komari 地址")
	}
	headers := map[string]string{}
	if key := text(settings, "probeApiKey"); key != "" {
		headers["Authorization"] = "Bearer " + key
	}
	var response struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := a.externalJSON(ctx, "POST", base+"/api/rpc2", headers, map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, &response); err != nil {
		return err
	}
	if len(response.Error) > 0 && string(response.Error) != "null" {
		return errors.New("Komari 读取权限或接口错误")
	}
	if len(response.Result) == 0 || string(response.Result) == "null" {
		return errors.New("Komari 未返回有效数据")
	}
	return json.Unmarshal(response.Result, out)
}

// History reads query the Komari controller, never dispatch work to an Agent.
func (a *App) komariHistory(ctx context.Context, server store.Record, hours int, network bool, target string) ([]store.Metric, string, error) {
	uuid := text(server.Data, "komariUUID")
	if uuid == "" {
		return nil, "", nil
	}
	var settings map[string]any
	if err := a.DB.GetSetting(ctx, "settings", &settings); err != nil {
		return nil, "", err
	}
	params := map[string]any{"uuid": uuid, "hours": hours, "maxCount": 4000, "type": "load", "load_type": "all"}
	if network {
		params["type"] = "ping"
		params["task_id"] = -1
	}
	var response struct {
		Records json.RawMessage  `json:"records"`
		Tasks   []map[string]any `json:"tasks"`
	}
	if err := a.komariRPC(ctx, settings, "common:getRecords", params, &response); err != nil {
		return nil, "", err
	}
	var records []map[string]any
	method := ""
	taskID := float64(-1)
	if network {
		index, err := strconv.Atoi(target)
		if err != nil || index < 0 {
			return nil, "", errors.New("网络监测序号无效")
		}
		sort.Slice(response.Tasks, func(i, j int) bool { return number(response.Tasks[i], "id") < number(response.Tasks[j], "id") })
		if index >= len(response.Tasks) {
			return nil, "", nil
		}
		taskID = number(response.Tasks[index], "id")
		method = text(response.Tasks[index], "type")
		if err := json.Unmarshal(response.Records, &records); err != nil {
			return nil, "", err
		}
	} else {
		var grouped map[string][]map[string]any
		if err := json.Unmarshal(response.Records, &grouped); err != nil {
			return nil, "", err
		}
		records = grouped[uuid]
	}
	out := []store.Metric{}
	now := time.Now()
	sort.Slice(records, func(i, j int) bool {
		return dateTime(text(records[i], "time")).Before(dateTime(text(records[j], "time")))
	})
	previousLatency := float64(-1)
	for _, record := range records {
		at, err := time.Parse(time.RFC3339Nano, text(record, "time"))
		if err != nil || at.After(now.Add(time.Minute)) || at.Before(now.Add(-time.Duration(hours)*time.Hour)) {
			continue
		}
		if client := text(record, "client"); client != "" && client != uuid {
			continue
		}
		values := map[string]any{}
		if network {
			if number(record, "task_id") != taskID || !finiteNumeric(record["value"]) {
				continue
			}
			values["sampleId"] = server.ID + "/" + target
			values["method"] = method
			values["failure_percent"] = 0
			if number(record, "value") < 0 {
				values["failure_percent"] = 100
			} else {
				values["average_ms"] = record["value"]
				latency := number(record, "value")
				if previousLatency >= 0 {
					values["jitter_ms"] = math.Abs(latency - previousLatency)
				}
				previousLatency = latency
			}
		} else {
			for from, to := range komariMetricNames {
				if finiteNumeric(record[from]) {
					values[to] = record[from]
				}
			}
		}
		out = append(out, store.Metric{RecordedAt: at, Values: values})
	}
	return out, method, nil
}
