package store

import (
	"log/slog"
	"strings"
)

// SetEventLog is configured before serving requests. Task state remains in SQL
// for dispatch/recovery; its human-readable execution history lives in files.
func (s *Store) SetEventLog(write func(map[string]any) error) { s.eventLog = write }
func (s *Store) logTask(t Task) {
	if s.eventLog == nil || strings.HasPrefix(t.Kind, "logs.") || t.ActorID == "scheduler" {
		return
	}
	category := "system"
	if t.ServerID != "" {
		category = "agent"
	}
	if t.ActorID == "scheduler" {
		category = "schedule"
	}
	level := "INFO"
	if t.Status == "failed" {
		level = "ERROR"
	}
	if t.Status == "unknown" || t.Status == "unsupported" {
		level = "WARN"
	}
	e := s.eventLog(map[string]any{"time": t.UpdatedAt, "category": category, "level": level, "event": t.Kind, "taskId": t.ID, "serverId": t.ServerID, "status": t.Status, "startedAt": t.CreatedAt, "durationMs": t.UpdatedAt.Sub(t.CreatedAt).Milliseconds(), "message": t.Error})
	if e != nil {
		slog.Error("task log write failed", "taskId", t.ID, "error", e)
	}
}
