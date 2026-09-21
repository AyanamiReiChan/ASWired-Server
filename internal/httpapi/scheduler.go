package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"time"
)

func (a *App) startJob(ctx context.Context, key string, run func(context.Context)) {
	a.mu.Lock()
	if a.jobs == nil {
		a.jobs = map[string]bool{}
	}
	if a.closing || a.recoveryRequired || a.jobs[key] || len(a.jobs) >= 16 {
		a.mu.Unlock()
		return
	}
	category := strings.SplitN(key, ":", 2)[0]
	same := 0
	for running := range a.jobs {
		if strings.SplitN(running, ":", 2)[0] == category {
			same++
		}
	}
	if same >= 4 {
		a.mu.Unlock()
		return
	}
	a.jobs[key] = true
	a.background.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.background.Done()
		defer func() { a.mu.Lock(); delete(a.jobs, key); a.mu.Unlock() }()
		jobctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		a.stateMu.RLock()
		defer a.stateMu.RUnlock()
		if jobctx.Err() != nil {
			return
		}
		run(jobctx)
	}()
}
func (a *App) maintainSchedules(ctx context.Context) {
	now := time.Now()
	schedules, e := a.DB.ListRecords(ctx, "schedules", "")
	if e != nil {
		return
	}
	for _, schedule := range schedules {
		if !boolean(schedule.Data, "enabled") {
			continue
		}
		next := dateTime(text(schedule.Data, "nextRun"))
		if !next.IsZero() && now.Before(next) {
			continue
		}
		record := schedule
		a.startJob(ctx, "schedule:"+record.ID, func(ctx context.Context) { a.runSchedule(ctx, record) })
	}
	sources, e := a.DB.ListRecords(ctx, "sources", "")
	if e == nil {
		for _, source := range sources {
			seconds := number(source.Data, "intervalSeconds")
			if seconds < 30 || disabledStatus(source.Data) || now.Before(dateTime(text(source.Data, "nextAttempt"))) {
				continue
			}
			last := dateTime(text(source.Data, "lastAttempt"))
			if now.Sub(last) < time.Duration(seconds)*time.Second {
				continue
			}
			rec := source
			a.startJob(ctx, "source:"+rec.ID, func(ctx context.Context) {
				rec.Data["lastAttempt"] = time.Now().UTC().Format(time.RFC3339)
				rec, e := a.DB.SaveRecord(ctx, rec)
				if e != nil {
					return
				}
				_, err := a.syncSource(ctx, rec.ID)
				latest, e := a.DB.GetRecord(ctx, "sources", rec.ID)
				if e != nil {
					return
				}
				if err != nil {
					latest.Data["lastError"] = err.Error()
					latest.Data["status"] = "同步失败"
					failures := int(number(latest.Data, "failureCount")) + 1
					if failures > 8 {
						failures = 8
					}
					latest.Data["failureCount"] = failures
					delay := time.Minute * time.Duration(1<<uint(failures-1))
					latest.Data["nextAttempt"] = time.Now().Add(delay).UTC().Format(time.RFC3339)
				} else {
					latest.Data["lastError"] = ""
					latest.Data["failureCount"] = 0
					delete(latest.Data, "nextAttempt")
				}
				_, _ = a.DB.SaveRecord(ctx, latest)
			})
		}
	}
	var settings map[string]any
	_ = a.DB.GetSetting(ctx, "settings", &settings)
	if komariBaseURL(settings) != "" {
		state, _ := a.DB.GetRecord(ctx, "_maintenance", "komari")
		last := dateTime(text(state.Data, "lastAttempt"))
		if now.Sub(last) > 30*time.Second {
			a.startJob(ctx, "komari", func(ctx context.Context) {
				data := map[string]any{"lastAttempt": time.Now().UTC().Format(time.RFC3339)}
				_, e := a.syncKomari(ctx, true)
				if e != nil {
					data["error"] = e.Error()
				} else {
					data["success"] = true
				}
				old, _ := a.DB.GetRecord(ctx, "_maintenance", "komari")
				_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_maintenance", ID: "komari", Version: old.Version, Data: data})
			})
		}
	}
}
func (a *App) runSchedule(ctx context.Context, schedule store.Record) {
	interval := number(schedule.Data, "intervalSeconds")
	if interval < 30 || interval > 365*24*3600 {
		return
	}
	schedule.Data["nextRun"] = time.Now().UTC().Add(time.Duration(interval) * time.Second).Format(time.RFC3339)
	claimed, claimErr := a.DB.SaveRecord(ctx, schedule)
	if claimErr != nil {
		return
	}
	schedule = claimed
	action := text(schedule.Data, "action")
	params, _ := schedule.Data["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	actor := store.User{ID: "scheduler", Username: "scheduler", Role: "admin"}
	task := store.Task{ID: newID(), ActorID: actor.ID, Kind: action, Status: "running", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	task.Input, _ = json.Marshal(map[string]any{"scheduleId": schedule.ID, "action": action})
	savedTask, saveErr := a.DB.SaveTask(ctx, task)
	if saveErr != nil {
		return
	}
	task = savedTask
	var result map[string]any
	var e error
	switch action {
	case "source.sync":
		result, e = a.syncSource(ctx, text(schedule.Data, "targetId"))
	case "backup.create":
		result, e = a.createBackup(ctx, actor)
	case "backup.remote.upload":
		result, e = a.remoteBackup(ctx, actor, action, params)
	case "notification.test":
		result, e = a.notificationTest(ctx, actor, text(schedule.Data, "targetId"), params)
	case "notification.daily":
		var message string
		message, e = a.dailyMessage(ctx, time.Now())
		if e == nil {
			params["message"] = message
			params["event"] = "report.daily"
			result, e = a.notificationTest(ctx, actor, text(schedule.Data, "targetId"), params)
		}
	case "komari.sync":
		result, e = a.syncKomari(ctx, true)
	default:
		e = errors.New("定时任务动作不在允许列表")
	}
	task.Status = "success"
	if e != nil {
		task.Status = "failed"
		task.Error = e.Error()
	}
	task.Result, _ = json.Marshal(result)
	_ = a.writeEventLog(map[string]any{"category": "schedule", "event": action, "name": defaultText(schedule.Data, "name", action), "startedAt": task.CreatedAt, "durationMs": time.Since(task.CreatedAt).Milliseconds(), "status": task.Status, "message": task.Error, "details": result, "taskId": task.ID})
	task.UpdatedAt = time.Now().UTC()
	_, _ = a.DB.SaveTask(ctx, task)
	latest, err := a.DB.GetRecord(ctx, "schedules", schedule.ID)
	if err != nil {
		return
	}
	latest.Data["lastRun"] = task.UpdatedAt.Format(time.RFC3339)
	latest.Data["lastStatus"] = task.Status
	latest.Data["lastError"] = task.Error
	latest.Data["lastTaskId"] = task.ID
	latest.Data["nextRun"] = task.UpdatedAt.Add(time.Duration(interval) * time.Second).Format(time.RFC3339)
	if e == nil {
		latest.Data["lastSuccess"] = task.UpdatedAt.Format(time.RFC3339)
	}
	_, _ = a.DB.SaveRecord(ctx, latest)
	if a.LogFiles == nil {
		a.audit(ctx, actor, "schedule.run", schedule.ID, map[string]any{"taskId": task.ID, "status": task.Status})
	}
}
func validateSchedule(row map[string]any) error {
	if !boolean(row, "enabled") {
		return nil
	}
	seconds := number(row, "intervalSeconds")
	if seconds < 30 || seconds > 365*24*3600 {
		return errors.New("执行间隔须为30秒至365天")
	}
	switch text(row, "action") {
	case "source.sync", "backup.create", "backup.remote.upload", "notification.test", "notification.daily", "komari.sync":
		return nil
	}
	return fmt.Errorf("不支持的定时动作%s", text(row, "action"))
}
