package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

// Immutable, authenticated response baselines. Eviction or a controller restart
// simply causes a full reset; a cursor never grants access to stored data.
type browserSnapshot struct {
	scope string
	data  map[string]any
	at    time.Time
	bytes int
}

func indexedRows(rows []map[string]any) (map[string]any, []string) {
	indexed, order := map[string]any{}, []string{}
	for _, row := range rows {
		id, _ := row["id"].(string)
		indexed[id] = row
		order = append(order, id)
	}
	return indexed, order
}

// Objects are patched by field, including nested live observations. Arrays are
// replaced. Explicit removal paths distinguish deletion from a JSON null value.
func browserDiff(old, next map[string]any, path []string, removed *[][]string) map[string]any {
	changed := map[string]any{}
	for key, value := range next {
		prior, exists := old[key]
		if exists && reflect.DeepEqual(prior, value) {
			continue
		}
		before, oldMap := prior.(map[string]any)
		after, newMap := value.(map[string]any)
		if exists && oldMap && newMap {
			patch := browserDiff(before, after, append(append([]string{}, path...), key), removed)
			if len(patch) > 0 {
				changed[key] = patch
			}
		} else {
			changed[key] = value
		}
	}
	for key := range old {
		if _, exists := next[key]; !exists {
			*removed = append(*removed, append(append([]string{}, path...), key))
		}
	}
	return changed
}

func (a *App) browserResponse(w http.ResponseWriter, r *http.Request, value map[string]any) {
	// Freeze and normalize structs, times and integer values before caching.
	raw, err := json.Marshal(value)
	if err != nil {
		fail(w, 500, "encoding_error", "状态编码失败")
		return
	}
	data := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&data) != nil {
		fail(w, 500, "encoding_error", "状态编码失败")
		return
	}
	query := r.URL.Query()
	cursor := query.Get("cursor")
	query.Del("cursor")
	u := current(r)
	scope := u.ID + "\x00" + u.Role + "\x00" + r.URL.Path + "?" + query.Encode()
	sum := sha256.Sum256(append([]byte(scope+"\x00"), raw...))
	revision := hex.EncodeToString(sum[:])
	now := time.Now()
	a.browserMu.Lock()
	if a.browserSnapshots == nil {
		a.browserSnapshots = map[string]browserSnapshot{}
	}
	old, found := a.browserSnapshots[cursor]
	found = found && old.scope == scope && now.Sub(old.at) < 15*time.Minute
	for key, entry := range a.browserSnapshots {
		if now.Sub(entry.at) >= 15*time.Minute {
			delete(a.browserSnapshots, key)
		}
	}
	// Bound retained serialized bytes and entry count across all users/resources.
	for {
		total := len(raw)
		oldest := ""
		var oldestAt time.Time
		for key, entry := range a.browserSnapshots {
			total += entry.bytes
			if oldest == "" || entry.at.Before(oldestAt) {
				oldest, oldestAt = key, entry.at
			}
		}
		if len(a.browserSnapshots) < 64 && total <= 16<<20 || oldest == "" {
			break
		}
		delete(a.browserSnapshots, oldest)
	}
	if len(raw) <= 16<<20 {
		a.browserSnapshots[revision] = browserSnapshot{scope: scope, data: data, at: now, bytes: len(raw)}
	}
	a.browserMu.Unlock()
	w.Header().Set("Cache-Control", "private, no-store")
	if !found {
		respond(w, 200, map[string]any{"cursor": revision, "reset": true, "data": data})
		return
	}
	removed := [][]string{}
	patch := browserDiff(old.data, data, nil, &removed)
	respond(w, 200, map[string]any{"cursor": revision, "base": cursor, "changes": patch, "removed": removed})
}

func (a *App) browserState(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	data, order := map[string]any{}, map[string]any{}
	for _, collection := range collections {
		if u.Role != "admin" && adminOnlyCollection(collection) {
			continue
		}
		rows, err := a.visibleRows(r, collection)
		if err != nil {
			fail(w, 500, "storage_error", "读取工作区失败")
			return
		}
		data[collection], order[collection] = indexedRows(rows)
	}
	pending := 0
	if u.Role == "admin" {
		if err := a.DB.DB().QueryRowContext(r.Context(), `SELECT COUNT(*) FROM tasks WHERE status IN ('queued','running') AND kind NOT IN ('logs.read','logs.remove')`).Scan(&pending); err != nil {
			fail(w, 500, "storage_error", "读取任务计数失败")
			return
		}
	}
	a.browserResponse(w, r, map[string]any{"user": u, "data": data, "order": order, "settings": a.settingsMap(r), "capabilities": capabilityMap(), "pendingTasks": pending})
}

// Task details (including potentially large results) stay on the existing
// authenticated single-task endpoint. Lists are only requested by their pages.
func (a *App) browserTasks(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			fail(w, 400, "invalid_limit", "任务数量须为 1 至 1000")
			return
		}
		limit = parsed
	}
	tasks, err := a.DB.ListTasks(r.Context(), "", limit)
	if err != nil {
		fail(w, 500, "storage_error", "读取任务失败")
		return
	}
	rows := []map[string]any{}
	for _, task := range tasks {
		row := taskRow(task)
		delete(row, "result")
		rows = append(rows, row)
	}
	indexed, order := indexedRows(rows)
	a.browserResponse(w, r, map[string]any{"rows": indexed, "order": order})
}
