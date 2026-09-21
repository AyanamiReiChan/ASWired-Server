package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

func (s *Store) AppendAudit(ctx context.Context, e AuditEvent) error {
	if e.ID == "" || strings.TrimSpace(e.Action) == "" {
		return ErrInvalid
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	if s.eventLog != nil {
		return s.eventLog(map[string]any{"time": e.CreatedAt, "event": e.Action, "actor": e.ActorID, "target": e.Target, "details": e.Details, "id": e.ID})
	}
	raw, err := s.encodeJSON(e.Details)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO audit_events(id,actor_id,action,target,details,created_at) VALUES(?,?,?,?,?,?)`), e.ID, e.ActorID, e.Action, e.Target, string(raw), stamp(e.CreatedAt))
	return translate(err)
}

func boundedLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 10000 {
		return 10000
	}
	return limit
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEvent, error) {
	if s.eventLog != nil {
		return []AuditEvent{}, nil
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT id,actor_id,action,target,details,created_at FROM audit_events ORDER BY created_at DESC,id DESC LIMIT ?`), boundedLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]AuditEvent, 0)
	for rows.Next() {
		var e AuditEvent
		var raw, created string
		if err := rows.Scan(&e.ID, &e.ActorID, &e.Action, &e.Target, &raw, &created); err != nil {
			return nil, err
		}
		if err := s.decodeJSON([]byte(raw), &e.Details); err != nil {
			return nil, err
		}
		e.CreatedAt = parseStamp(created)
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *Store) AddMetric(ctx context.Context, m Metric) error {
	if m.ID == "" || m.ServerID == "" || m.Values == nil {
		return ErrInvalid
	}
	if m.RecordedAt.IsZero() {
		m.RecordedAt = time.Now().UTC()
	}
	raw, err := s.encodeJSON(m.Values)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO metrics(id,server_id,recorded_at,data) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING`), m.ID, m.ServerID, stamp(m.RecordedAt), string(raw))
	return translate(err)
}

func (s *Store) ListMetrics(ctx context.Context, serverID string, since time.Time, limit int) ([]Metric, error) {
	query := `SELECT id,server_id,recorded_at,data FROM metrics WHERE recorded_at>=?`
	args := []any{stamp(since)}
	if serverID != "" {
		query += ` AND server_id=?`
		args = append(args, serverID)
	}
	query += ` ORDER BY recorded_at DESC,id DESC LIMIT ?`
	args = append(args, boundedLimit(limit))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Metric, 0)
	for rows.Next() {
		var m Metric
		var raw, recorded string
		if err := rows.Scan(&m.ID, &m.ServerID, &recorded, &raw); err != nil {
			return nil, err
		}
		if err := s.decodeJSON([]byte(raw), &m.Values); err != nil {
			return nil, err
		}
		m.RecordedAt = parseStamp(recorded)
		result = append(result, m)
	}
	return result, rows.Err()
}

const taskColumns = `id,server_id,actor_id,kind,status,input,result,error,created_at,updated_at,COALESCE((SELECT data FROM records WHERE collection='_deletedTaskLogs' AND records.id=tasks.id),'')`

const visibleTaskLog = `NOT EXISTS(SELECT 1 FROM records WHERE collection='_deletedTaskLogs' AND records.id=tasks.id)`

func (s *Store) scanTask(row interface{ Scan(...any) error }) (Task, error) {
	var t Task
	var input, result, created, updated, deleted string
	if err := row.Scan(&t.ID, &t.ServerID, &t.ActorID, &t.Kind, &t.Status, &input, &result, &t.Error, &created, &updated, &deleted); err != nil {
		return t, translate(err)
	}
	if input != "" {
		if err := s.decodeJSON([]byte(input), &t.Input); err != nil {
			return t, err
		}
	}
	if result != "" {
		if err := s.decodeJSON([]byte(result), &t.Result); err != nil {
			return t, err
		}
	}
	if deleted != "" {
		var metadata struct {
			Reason string `json:"reason"`
		}
		if err := s.decodeJSON([]byte(deleted), &metadata); err != nil {
			return t, err
		}
		t.LogsDeleted = true
		t.LogReason = metadata.Reason
	}
	t.CreatedAt = parseStamp(created)
	t.UpdatedAt = parseStamp(updated)
	t.expectedStatus = t.Status
	t.expectedUpdatedAt = t.UpdatedAt
	return t, nil
}

func (s *Store) SaveTask(ctx context.Context, t Task) (Task, error) {
	if t.LogsDeleted {
		return Task{}, ErrConflict
	}
	if t.ID == "" || t.Kind == "" || t.Status == "" {
		return Task{}, ErrInvalid
	}
	if (len(t.Input) > 0 && !json.Valid(t.Input)) || (len(t.Result) > 0 && !json.Valid(t.Result)) {
		return Task{}, ErrInvalid
	}
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	input, result := "", ""
	if len(t.Input) > 0 {
		raw, err := s.encodeJSON(t.Input)
		if err != nil {
			return Task{}, err
		}
		input = string(raw)
	}
	if len(t.Result) > 0 {
		raw, err := s.encodeJSON(t.Result)
		if err != nil {
			return Task{}, err
		}
		result = string(raw)
	}
	var err error
	if t.expectedUpdatedAt.IsZero() {
		_, err = s.db.ExecContext(ctx, s.bind(`INSERT INTO tasks(id,server_id,actor_id,kind,status,input,result,error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`), t.ID, t.ServerID, t.ActorID, t.Kind, t.Status, input, result, t.Error, stamp(t.CreatedAt), stamp(t.UpdatedAt))
	} else {
		var updated sql.Result
		updated, err = s.db.ExecContext(ctx, s.bind(`UPDATE tasks SET status=?,result=?,error=?,updated_at=? WHERE id=? AND status=? AND updated_at=? AND `+visibleTaskLog), t.Status, result, t.Error, stamp(t.UpdatedAt), t.ID, t.expectedStatus, stamp(t.expectedUpdatedAt))
		if err == nil {
			count, e := updated.RowsAffected()
			if e != nil {
				return Task{}, e
			}
			if count != 1 {
				return Task{}, ErrConflict
			}
		}
	}
	if err != nil {
		return Task{}, translate(err)
	}
	s.logTask(t)
	return s.GetTask(ctx, t.ID)
}

func (s *Store) GetTask(ctx context.Context, id string) (Task, error) {
	return s.scanTask(s.db.QueryRowContext(ctx, s.bind(`SELECT `+taskColumns+` FROM tasks WHERE id=?`), id))
}

func (s *Store) ListTasks(ctx context.Context, serverID string, limit int) ([]Task, error) {
	query := `SELECT ` + taskColumns + ` FROM tasks WHERE kind NOT IN ('logs.read','logs.remove') AND ` + visibleTaskLog
	args := []any{}
	if serverID != "" {
		query += ` AND server_id=?`
		args = append(args, serverID)
	}
	query += ` ORDER BY created_at DESC,id DESC LIMIT ?`
	args = append(args, boundedLimit(limit))
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Task, 0)
	for rows.Next() {
		t, err := s.scanTask(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}
	return result, rows.Err()
}
