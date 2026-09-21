package httpapi

import (
	"context"
	"time"
)

// A maintenance pass is a scan, not proof that each dispatched command succeeded.
func (a *App) loggedMaintenance(ctx context.Context, name string, run func(context.Context)) {
	started := time.Now()
	run(ctx)
	status := "completed"
	message := "本轮检查完成，异步任务结果见 Agent 日志"
	if ctx.Err() != nil {
		status = "failed"
		message = ctx.Err().Error()
	}
	_ = a.writeEventLog(map[string]any{"category": "schedule", "event": name, "name": name, "startedAt": started.UTC(), "durationMs": time.Since(started).Milliseconds(), "status": status, "message": message})
}
