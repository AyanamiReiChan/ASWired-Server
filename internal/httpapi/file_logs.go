package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/logfiles"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var privateLogKey = regexp.MustCompile(`(?i)password|secret|token|credential|private.?key|authorization|cookie|certificate|config|pem|uri$`)
var securityLogEvent = regexp.MustCompile(`^(auth\.|identity\.|login|logout|token\.|password\.|session\.|account\.|security\.|entrance\.|qr\.)`)

func safeLogValue(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range value {
			if privateLogKey.MatchString(key) {
				out[key] = "[已隐藏]"
			} else {
				out[key] = safeLogValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = safeLogValue(item)
		}
		return out
	default:
		return v
	}
}
func (a *App) EnableFileLogs(system *logfiles.Manager) error {
	a.LogFiles = system
	a.LogStreams = map[string]*logfiles.Manager{"system": system}
	for _, stream := range []string{"schedule", "security"} {
		manager, err := logfiles.OpenNamed(filepath.Join(a.Config.DataDir, "logs"), stream+".log", 50<<20, 5)
		if err != nil {
			a.CloseFileLogs()
			return err
		}
		a.LogStreams[stream] = manager
	}
	a.DB.SetEventLog(a.writeEventLog)
	return nil
}
func (a *App) CloseFileLogs() {
	for key, manager := range a.LogStreams {
		if key != "system" {
			manager.Close()
		}
	}
}
func (a *App) logStream(name string) *logfiles.Manager {
	if name == "" || name == "system" {
		return a.LogFiles
	}
	return a.LogStreams[name]
}
func (a *App) writeEventLog(event map[string]any) error {
	category := text(event, "category")
	action := text(event, "event")
	if category == "" {
		category = "system"
		if securityLogEvent.MatchString(action) {
			category = "security"
		} else if strings.HasPrefix(action, "schedule.") {
			category = "schedule"
		}
	}
	stream := category
	if stream == "agent" {
		stream = "system"
	}
	manager := a.logStream(stream)
	if manager == nil {
		return nil
	}
	event["category"] = category
	if event["time"] == nil {
		event["time"] = time.Now().UTC()
	}
	if event["level"] == nil {
		event["level"] = "INFO"
	}
	return manager.Append(safeLogValue(event).(map[string]any))
}
func (a *App) readFileLogs(w http.ResponseWriter, r *http.Request) {
	manager := a.logStream(r.URL.Query().Get("stream"))
	if manager == nil {
		fail(w, 503, "unavailable", "日志文件未启用")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	result, err := manager.Read(limit)
	if err != nil {
		fail(w, 500, "storage_error", "读取日志失败")
		return
	}
	respond(w, 200, result)
}

// Agent reads use the authenticated command channel for all three transports.
// These short-lived commands are consumed and removed, never used as log storage.
func (a *App) agentFileLogs(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Operation string `json:"operation"`
		Stream    string `json:"stream"`
		Name      string `json:"name"`
		All       bool   `json:"all"`
		Confirm   bool   `json:"confirm"`
		Limit     int    `json:"limit"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Operation != "read" && input.Operation != "remove" {
		fail(w, 400, "invalid_operation", "日志操作无效")
		return
	}
	if input.Operation == "remove" && !input.Confirm {
		fail(w, 400, "confirmation_required", "请确认日志清理范围")
		return
	}
	if input.Stream != "agent" && input.Stream != "xray-access" && input.Stream != "xray-error" {
		fail(w, 400, "invalid_stream", "日志类型无效")
		return
	}
	if input.Limit < 1 {
		input.Limit = 200
	}
	if input.Limit > 2000 {
		input.Limit = 2000
	}
	a.mu.Lock()
	peer := a.peers[r.PathValue("id")]
	online := peer != nil && time.Since(peer.LastSeen) < 30*time.Second
	a.mu.Unlock()
	if !online {
		fail(w, 409, "agent_offline", "Agent 离线，无法读取或清理日志")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	task, err := a.queue(ctx, current(r), r.PathValue("id"), "logs."+input.Operation, map[string]any{"stream": input.Stream, "name": input.Name, "all": input.All, "confirm": input.Confirm, "limit": input.Limit})
	if err != nil {
		fail(w, 400, "log_request_failed", err.Error())
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = a.DB.DB().ExecContext(ctx, a.DB.Bind(`DELETE FROM tasks WHERE id=? AND kind IN ('logs.read','logs.remove')`), task.ID)
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fail(w, 504, "agent_timeout", "Agent 日志操作尚未返回，请刷新确认结果")
			return
		case <-ticker.C:
			latest, err := a.DB.GetTask(ctx, task.ID)
			if err != nil {
				fail(w, 500, "storage_error", "读取日志结果失败")
				return
			}
			if latest.Status == "queued" || latest.Status == "running" {
				continue
			}
			if latest.Status != "success" {
				fail(w, 502, "agent_log_failed", latest.Error)
				return
			}
			var result map[string]any
			if err = json.Unmarshal(latest.Result, &result); err != nil {
				fail(w, 502, "agent_log_failed", errors.New("Agent 日志结果无效").Error())
				return
			}
			respond(w, 200, result)
			return
		}
	}
}
