package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

const logRetentionDays = 7

func taskLogDeleteReason(task store.Task, now time.Time) string {
	if !store.TerminalTaskStatus(task.Status) {
		return "任务仍在等待执行或确认结果，不能删除日志"
	}
	if (task.Kind == "source.fetch" || task.Kind == "federation.identity") && now.Sub(task.UpdatedAt) < time.Minute {
		return "结果正在供关联操作读取，请在任务结束一分钟后重试"
	}
	return ""
}

func taskLogRetirementReason(task store.Task) string {
	reason := ""
	if task.Kind == "core.policy.apply" && task.Status == "superseded" && task.Error == unusedInitialPolicyMessage {
		reason = "initial_policy_unused"
	}
	return reason
}

func (a *App) clearTaskLog(ctx context.Context, task store.Task, now time.Time) error {
	return a.DB.DeleteTaskLog(ctx, task, now, taskLogRetirementReason(task))
}

func (a *App) deleteLog(w http.ResponseWriter, r *http.Request) {
	if current(r).Role != "admin" {
		fail(w, http.StatusForbidden, "forbidden", "只有管理员可以删除日志")
		return
	}
	collection, id := r.PathValue("collection"), r.PathValue("id")
	var err error
	if collection == "tasks" {
		task, e := a.DB.GetTask(r.Context(), id)
		if e != nil || task.LogsDeleted {
			if e == nil || errors.Is(e, store.ErrNotFound) {
				fail(w, http.StatusNotFound, "not_found", "任务日志不存在")
			} else {
				fail(w, http.StatusInternalServerError, "storage_error", "读取任务日志失败")
			}
			return
		}
		if reason := taskLogDeleteReason(task, time.Now()); reason != "" {
			fail(w, http.StatusConflict, "log_in_use", reason)
			return
		}
		err = a.clearTaskLog(r.Context(), task, time.Now())
	} else {
		err = a.DB.DeleteAudit(r.Context(), id)
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			fail(w, http.StatusNotFound, "not_found", "日志不存在")
		case errors.Is(err, store.ErrTaskLogProtected):
			fail(w, http.StatusConflict, "log_in_use", "关联操作仍在使用任务结果，请稍后重试")
		case errors.Is(err, store.ErrConflict):
			fail(w, http.StatusConflict, "log_changed", "任务状态已变化，请刷新后重试")
		default:
			fail(w, http.StatusInternalServerError, "storage_error", "删除日志失败")
		}
		return
	}
	a.audit(r.Context(), current(r), "log.delete", collection+"/"+id, nil)
	respond(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *App) maintainLogRetention(ctx context.Context, now time.Time) {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	a.maintainKomariSessions(ctx, now)
	a.mu.Lock()
	unavailable := a.recoveryRequired || a.closing
	a.mu.Unlock()
	if unavailable {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cutoff := now.Add(-logRetentionDays * 24 * time.Hour)
	after := time.Time{}
	afterID := ""
	for {
		tasks, err := a.DB.ExpiredTaskLogs(ctx, cutoff, after, afterID, 250)
		if err != nil {
			slog.Error("task log retention", "error", err)
			return
		}
		for _, task := range tasks {
			if err := a.clearTaskLog(ctx, task, now); err != nil && !errors.Is(err, store.ErrTaskLogProtected) && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
				slog.Error("task log retention", "error", err)
				return
			}
		}
		if len(tasks) < 250 {
			break
		}
		last := tasks[len(tasks)-1]
		after, afterID = last.UpdatedAt, last.ID
	}
	if err := a.DB.DeleteAuditBefore(ctx, cutoff); err != nil {
		slog.Error("audit log retention", "error", err)
	}
}

func (a *App) logMaintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	a.maintainLogRetention(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			a.maintainLogRetention(ctx, now)
		}
	}
}
