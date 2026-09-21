package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrTaskLogProtected = errors.New("task log is still needed by an active operation")

func TerminalTaskStatus(status string) bool {
	switch status {
	case "success", "failed", "unsupported", "superseded":
		return true
	}
	return false
}

func (s *Store) HasOtherTask(ctx context.Context, serverID, kind, exceptID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM tasks WHERE server_id=? AND kind=? AND id<>?`), serverID, kind, exceptID).Scan(&count)
	return count > 0, err
}

func (s *Store) DeleteTaskLog(ctx context.Context, task Task, now time.Time, reason string) error {
	if task.LogsDeleted {
		return ErrNotFound
	}
	if !TerminalTaskStatus(task.Status) {
		return ErrTaskLogProtected
	}
	if (task.Kind == "source.fetch" || task.Kind == "federation.identity") && now.Sub(task.UpdatedAt) < time.Minute {
		return ErrTaskLogProtected
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.clearTaskLogTx(ctx, tx, task, now, reason); err != nil {
		return err
	}
	protected, err := s.protectedForwardTaskIDsTx(ctx, tx, false)
	if err != nil {
		return err
	}
	if protected[task.ID] {
		return ErrTaskLogProtected
	}
	return tx.Commit()
}

func (s *Store) clearTaskLogTx(ctx context.Context, tx *sql.Tx, task Task, now time.Time, reason string) error {
	changed, err := tx.ExecContext(ctx, s.bind(`UPDATE tasks SET input='',result='',error='' WHERE id=? AND status=? AND updated_at=? AND `+visibleTaskLog), task.ID, task.Status, stamp(task.UpdatedAt))
	if err != nil {
		return err
	}
	count, err := changed.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	_, err = s.saveRecordTx(ctx, tx, Record{Collection: "_deletedTaskLogs", ID: task.ID, Data: map[string]any{"reason": reason}, CreatedAt: now, UpdatedAt: now})
	return err
}

func (s *Store) protectedForwardTaskIDsTx(ctx context.Context, tx *sql.Tx, lock bool) (map[string]bool, error) {
	query := `SELECT data FROM records WHERE collection='_forwardChains'`
	if lock && s.driver == "pgx" {
		query += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	protected := map[string]bool{}
	for rows.Next() {
		var raw string
		var data struct {
			Status        string `json:"status"`
			CurrentTaskID string `json:"currentTaskId"`
		}
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = s.decodeJSON([]byte(raw), &data); err != nil {
			return nil, err
		}
		if data.CurrentTaskID != "" && (data.Status == "ready" || data.Status == "waiting" || data.Status == "dispatching") {
			protected[data.CurrentTaskID] = true
		}
	}
	return protected, rows.Err()
}

func (s *Store) ExpiredTaskLogs(ctx context.Context, before, after time.Time, afterID string, limit int) ([]Task, error) {
	query := `SELECT ` + taskColumns + ` FROM tasks WHERE status IN ('success','failed','unsupported','superseded') AND updated_at<? AND ` + visibleTaskLog
	args := []any{stamp(before)}
	if !after.IsZero() {
		query += ` AND (updated_at>? OR (updated_at=? AND id>?))`
		args = append(args, stamp(after), stamp(after), afterID)
	}
	query += ` ORDER BY updated_at,id LIMIT ?`
	args = append(args, boundedLimit(limit))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		task, err := s.scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAudit(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM audit_events WHERE id=?`), id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAuditBefore(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM audit_events WHERE created_at<?`), stamp(before))
	return err
}
