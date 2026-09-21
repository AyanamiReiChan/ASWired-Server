package store

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Store) ListPendingTasks(ctx context.Context, serverID string, limit int) ([]Task, error) {
	return s.listTasksByStatus(ctx, serverID, "queued", limit)
}
func (s *Store) ListRunningTasks(ctx context.Context, serverID string, limit int) ([]Task, error) {
	return s.listTasksByStatus(ctx, serverID, "running", limit)
}

func (s *Store) HasActiveTask(ctx context.Context, serverID, kind string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM tasks WHERE server_id=? AND kind=? AND status IN ('queued','running')`), serverID, kind).Scan(&count)
	return count > 0, err
}
func (s *Store) listTasksByStatus(ctx context.Context, serverID, status string, limit int) ([]Task, error) {
	query := `SELECT ` + taskColumns + ` FROM tasks WHERE status=?`
	args := []any{status}
	if serverID != "" {
		query += ` AND server_id=?`
		args = append(args, serverID)
	}
	// Configuration creates the inbounds that queued user syncs depend on.
	// It must remain reachable even when more than a page of syncs is waiting.
	if status == "queued" {
		query += ` ORDER BY CASE WHEN kind='core.config.apply' THEN 0 ELSE 1 END,created_at,id LIMIT ?`
	} else {
		query += ` ORDER BY created_at,id LIMIT ?`
	}
	args = append(args, boundedLimit(limit))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		task, e := s.scanTask(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, task)
	}
	return out, rows.Err()
}

func (s *Store) CreateTaskWithRecords(ctx context.Context, t Task, records []Record) (Task, error) {
	return s.CreateTaskWithChanges(ctx, t, records, nil)
}

// CreateTaskWithChanges atomically commits a command and its desired-state changes.
// Deletions use record versions so a concurrent editor cannot lose an update.
func (s *Store) CreateTaskWithChanges(ctx context.Context, t Task, records, deleted []Record) (Task, error) {
	if t.ID == "" || t.Kind == "" || t.Status != "queued" || !t.expectedUpdatedAt.IsZero() || len(t.Result) > 0 || t.Error != "" || (len(t.Input) > 0 && !json.Valid(t.Input)) {
		return Task{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, r := range records {
		key := r.Collection + "\x00" + r.ID
		if seen[key] {
			return Task{}, ErrInvalid
		}
		seen[key] = true
	}
	for _, r := range deleted {
		key := r.Collection + "\x00" + r.ID
		if seen[key] || r.Version < 1 || r.Collection == "subscriptions" {
			return Task{}, ErrInvalid
		}
		seen[key] = true
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Task{}, e
	}
	defer tx.Rollback()
	if s.driver == "sqlite" {
		if _, e = tx.ExecContext(ctx, `UPDATE records SET version=version WHERE 1=0`); e != nil {
			return Task{}, e
		}
	}
	for _, r := range records {
		if _, e = s.saveRecordTx(ctx, tx, r); e != nil {
			return Task{}, e
		}
	}
	for _, r := range deleted {
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM records WHERE collection=? AND id=? AND version=?`), r.Collection, r.ID, r.Version)
		if err != nil {
			return Task{}, translate(err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return Task{}, err
		}
		if count != 1 {
			return Task{}, ErrConflict
		}
	}
	input := ""
	if len(t.Input) > 0 {
		raw, err := s.encodeJSON(t.Input)
		if err != nil {
			return Task{}, err
		}
		input = string(raw)
	}
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	if _, e = tx.ExecContext(ctx, s.bind(`INSERT INTO tasks(id,server_id,actor_id,kind,status,input,result,error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`), t.ID, t.ServerID, t.ActorID, t.Kind, t.Status, input, "", "", stamp(t.CreatedAt), stamp(t.UpdatedAt)); e != nil {
		return Task{}, translate(e)
	}
	if e = tx.Commit(); e != nil {
		return Task{}, e
	}
	t.expectedStatus = t.Status
	t.expectedUpdatedAt = t.UpdatedAt
	s.logTask(t)
	return t, nil
}
