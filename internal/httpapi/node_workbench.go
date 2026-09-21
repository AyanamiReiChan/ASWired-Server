package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) registerNodeWorkbench(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/nodes/import/preview", a.withAdmin(a.nodeImport))
	mux.HandleFunc("POST /api/nodes/import", a.withAdmin(a.nodeImport))
	mux.HandleFunc("POST /api/nodes/metadata", a.withAdmin(a.nodeMetadata))
	mux.HandleFunc("GET /api/nodes/{id}/connection", a.withUser(a.nodeConnection))
	mux.HandleFunc("POST /api/nodes/{id}/speedtest", a.withAdmin(a.nodeSpeedtest))
}

func (a *App) nodeSpeedtest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		EndpointID     string `json:"endpointId"`
		SubscriptionID string `json:"subscriptionId"`
		Duration       int    `json:"duration"`
		Parallel       int    `json:"parallel"`
		DownloadURL    string `json:"downloadURL"`
		IPCheckURL     string `json:"ipCheckURL"`
		DownloadBytes  int64  `json:"downloadBytes"`
		LatencyOnly    bool   `json:"latencyOnly"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Duration < 1 || in.Duration > 30 || (in.Parallel != 1 && in.Parallel != 8 && in.Parallel != 16 && in.Parallel != 32 && in.Parallel != 64) {
		fail(w, 400, "invalid_measurement", "测试时长须为 1 至 30 秒，并发为 1、8、16、32 或 64")
		return
	}
	if in.DownloadBytes != 0 && in.DownloadBytes != 1<<20 && in.DownloadBytes != 4<<20 && in.DownloadBytes != 8<<20 && in.DownloadBytes != 16<<20 {
		fail(w, 400, "invalid_measurement", "数据量须为 1、4、8 或 16 MiB")
		return
	}
	node, err := a.DB.GetRecord(r.Context(), "nodes", r.PathValue("id"))
	if err != nil || disabledStatus(node.Data) {
		fail(w, 404, "node_unavailable", "节点不存在或已停用")
		return
	}
	var sub store.Record
	if boolean(node.Data, "managedInbound") {
		sub, err = a.DB.GetRecord(r.Context(), "subscriptions", in.SubscriptionID)
		if err != nil {
			fail(w, 400, "subscription_required", "受管节点测速须选择有效套餐实例")
			return
		}
		nodes, e := a.eligibleNodes(r.Context(), sub)
		allowed := false
		if e == nil {
			for _, candidate := range nodes {
				if candidate.ID == node.ID {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			fail(w, 403, "node_denied", "该实例无权使用此节点")
			return
		}
	}
	client, err := a.realitySubscriptionNode(r.Context(), node, sub)
	if err != nil {
		fail(w, 400, "invalid_node", err.Error())
		return
	}
	params := map[string]any{"node": clashNode(client), "nodeId": node.ID, "nodeName": text(node.Data, "name"), "subscriptionId": sub.ID, "duration_seconds": in.Duration, "parallel": in.Parallel, "url": in.DownloadURL, "ip_check_url": in.IPCheckURL}
	if in.DownloadBytes > 0 {
		params["download_bytes"] = in.DownloadBytes
	}
	if in.LatencyOnly {
		params["latency_only"] = true
	}
	task, err := a.queueHome(r.Context(), current(r), in.EndpointID, params)
	if err != nil {
		fail(w, 400, "speedtest_failed", err.Error())
		return
	}
	_, _ = a.DB.SaveRecord(r.Context(), store.Record{Collection: "speedtests", ID: task.ID, OwnerID: current(r).ID, Data: map[string]any{"nodeId": node.ID, "nodeName": text(node.Data, "name"), "endpointId": in.EndpointID, "status": "queued", "parallel": in.Parallel, "download_bytes": in.DownloadBytes, "latency_only": in.LatencyOnly, "testedAt": task.CreatedAt}})
	a.audit(r.Context(), current(r), "node.speedtest", node.ID, map[string]any{"taskId": task.ID, "endpointId": in.EndpointID, "subscriptionId": sub.ID})
	respond(w, 202, map[string]any{"task": taskRow(task)})
}

// Fingerprint the complete connection identity, including credentials. Equal
// endpoints with different users must never be merged.
func nodeImportIdentity(row map[string]any) string {
	if client, err := clientNodeFor(store.Record{Data: row}, store.Record{}); err == nil {
		identity := clashNode(client)
		delete(identity, "name")
		raw, _ := json.Marshal(identity)
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	identity := map[string]any{}
	for _, key := range []string{"host", "port", "protocol", "uuid", "security", "network", "sni", "publicKey", "shortId", "flow", "fingerprint"} {
		identity[key] = row[key]
	}
	raw, _ := json.Marshal(identity)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (a *App) nodeImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Lines   []string `json:"lines"`
		Content string   `json:"content"`
		Tags    []string `json:"tags"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Content == "" {
		in.Content = strings.Join(in.Lines, "\n")
	}
	entries, parseErr := nodeImportEntries(in.Content)
	if parseErr != nil {
		fail(w, 400, "invalid_import", parseErr.Error())
		return
	}
	if len(entries) == 0 || len(entries) > 500 {
		fail(w, 400, "invalid_import", "每次导入 1 至 500 个节点")
		return
	}
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	existing, err := a.DB.ListRecords(r.Context(), "nodes", "")
	if err != nil {
		fail(w, 503, "storage_error", "无法读取节点")
		return
	}
	seen := map[string]bool{}
	for _, row := range existing {
		if boolean(row.Data, "managedInbound") {
			continue
		}
		if normalized, e := normalizedProxyNode(row.Data, true); e == nil {
			seen[nodeImportIdentity(normalized)] = true
		}
	}
	preview := []any{}
	records := []store.Record{}
	invalid := false
	for i, entry := range entries {
		row, e := normalizedProxyNode(entry, true)
		item := map[string]any{"line": i + 1}
		if e != nil {
			item["error"] = e.Error()
			invalid = true
		} else {
			identity := nodeImportIdentity(row)
			item["duplicate"] = seen[identity]
			item["name"] = defaultText(row, "name", text(row, "host"))
			item["host"] = row["host"]
			item["port"] = row["port"]
			item["protocol"] = row["protocol"]
			item["transport"] = row["transport"]
			if !seen[identity] {
				row["name"] = item["name"]
				row["tags"] = in.Tags
				row["source"] = "手动导入"
				row["status"] = "启用"
				records = append(records, store.Record{Collection: "nodes", ID: newID(), Data: row})
				seen[identity] = true
			}
		}
		preview = append(preview, item)
	}
	if strings.HasSuffix(r.URL.Path, "/preview") {
		respond(w, 200, map[string]any{"rows": preview, "valid": !invalid, "count": len(records)})
		return
	}
	if invalid {
		respond(w, 400, map[string]any{"error": map[string]any{"code": "invalid_import", "message": "包含无效 URI，未保存任何节点"}, "rows": preview})
		return
	}
	saved, err := a.DB.CompareAndSaveRecords(r.Context(), records)
	if err != nil {
		fail(w, 409, "import_conflict", "导入未提交，请重新预览")
		return
	}
	a.audit(r.Context(), current(r), "node.import", "nodes", map[string]any{"count": len(saved)})
	respond(w, 201, map[string]any{"count": len(saved), "rows": preview})
}

// Bulk metadata changes are one version-checked transaction. Connection
// settings and runtime status are deliberately edited through the inbound.
func (a *App) nodeMetadata(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rows []struct {
			ID      string         `json:"id"`
			Version int64          `json:"recordVersion"`
			Patch   map[string]any `json:"patch"`
		} `json:"rows"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Rows) == 0 || len(in.Rows) > 500 {
		fail(w, 400, "invalid_batch", "每次修改 1 至 500 条节点")
		return
	}
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	records := []store.Record{}
	for _, change := range in.Rows {
		record, err := a.DB.GetRecord(r.Context(), "nodes", change.ID)
		if err != nil || change.Version != record.Version {
			fail(w, 409, "conflict", "节点已改变，请刷新重试")
			return
		}
		for key, value := range change.Patch {
			switch key {
			case "name", "tags", "description", "region", "weight", "visible", "sortOrder":
				record.Data[key] = value
			default:
				fail(w, 400, "invalid_patch", "批量操作仅允许修改显示信息")
				return
			}
		}
		if strings.TrimSpace(text(record.Data, "name")) == "" {
			fail(w, 400, "name_required", "节点名称不能为空")
			return
		}
		records = append(records, record)
	}
	if _, err := a.DB.CompareAndSaveRecords(r.Context(), records); err != nil {
		fail(w, 409, "conflict", "批量修改未提交，请刷新重试")
		return
	}
	a.audit(r.Context(), current(r), "node.metadata", "nodes", map[string]any{"count": len(records)})
	respond(w, 200, map[string]any{"count": len(records)})
}

func (a *App) nodeConnection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "private, no-store")
	sub, err := a.DB.GetRecord(r.Context(), "subscriptions", r.URL.Query().Get("subscriptionId"))
	if err != nil || sub.OwnerID != current(r).ID {
		fail(w, 403, "scope_denied", "请选择自己的有效套餐实例")
		return
	}
	if !membershipIPAllowed(sub, requestIP(r)) {
		fail(w, 403, "scope_denied", "当前地址不在套餐白名单内")
		return
	}
	nodes, err := a.eligibleNodes(r.Context(), sub)
	if err != nil {
		fail(w, 403, "subscription_inactive", err.Error())
		return
	}
	for _, node := range nodes {
		if node.ID == r.PathValue("id") {
			client, err := a.realitySubscriptionNode(r.Context(), node, sub)
			if err != nil {
				fail(w, 422, "invalid_node", err.Error())
				return
			}
			respond(w, 200, map[string]any{"uri": nodeURI(client), "clash": clashNode(client), "subscriptionId": sub.ID})
			return
		}
	}
	fail(w, 403, "node_denied", "该节点不在此套餐当前允许范围内")
}
