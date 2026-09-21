package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const MaxLogSelection = 10000

var ErrLogSelectionTooLarge = errors.New("log selection exceeds batch limit")
var ErrLogPreviewChanged = errors.New("log selection changed after preview")

type LogSelection struct {
	Total       int    `json:"total"`
	Deletable   int    `json:"deletable"`
	Protected   int    `json:"protected"`
	Fingerprint string `json:"fingerprint"`
}

type logSelectionEntry struct {
	ID        string
	Status    string
	Kind      string
	ServerID  string
	CreatedAt string
	UpdatedAt string
	Protected bool
	task      Task
}

func protectedTaskLog(task Task, now time.Time, forward map[string]bool) bool {
	return !TerminalTaskStatus(task.Status) || forward[task.ID] || (task.Kind == "source.fetch" || task.Kind == "federation.identity") && now.Sub(task.UpdatedAt) < time.Minute
}

func (s *Store) logSelectionTx(ctx context.Context, tx *sql.Tx, collection string, from, to, now time.Time, lock bool) (LogSelection, []logSelectionEntry, error) {
	if (collection != "tasks" && collection != "audit") || !from.Before(to) {
		return LogSelection{}, nil, ErrInvalid
	}
	query := `SELECT id,created_at FROM audit_events WHERE created_at>=? AND created_at<? ORDER BY id LIMIT ?`
	protected := map[string]bool{}
	if collection == "tasks" {
		var err error
		protected, err = s.protectedForwardTaskIDsTx(ctx, tx, lock)
		if err != nil {
			return LogSelection{}, nil, err
		}
		query = `SELECT id,server_id,kind,status,error,created_at,updated_at FROM tasks WHERE created_at>=? AND created_at<? AND ` + visibleTaskLog + ` ORDER BY id LIMIT ?`
	}
	if lock && s.driver == "pgx" {
		query += ` FOR UPDATE`
	}
	rows, err := tx.QueryContext(ctx, s.bind(query), stamp(from), stamp(to), MaxLogSelection+1)
	if err != nil {
		return LogSelection{}, nil, err
	}
	defer rows.Close()
	entries := []logSelectionEntry{}
	result := LogSelection{}
	for rows.Next() {
		entry := logSelectionEntry{}
		if collection == "tasks" {
			task := Task{}
			err = rows.Scan(&task.ID, &task.ServerID, &task.Kind, &task.Status, &task.Error, &entry.CreatedAt, &entry.UpdatedAt)
			task.CreatedAt = parseStamp(entry.CreatedAt)
			task.UpdatedAt = parseStamp(entry.UpdatedAt)
			entry.ID, entry.ServerID, entry.Kind, entry.Status, entry.task = task.ID, task.ServerID, task.Kind, task.Status, task
			entry.Protected = protectedTaskLog(task, now, protected)
		} else {
			err = rows.Scan(&entry.ID, &entry.CreatedAt)
		}
		if err != nil {
			return LogSelection{}, nil, err
		}
		entries = append(entries, entry)
		if len(entries) > MaxLogSelection {
			return LogSelection{}, nil, ErrLogSelectionTooLarge
		}
		result.Total++
		if entry.Protected {
			result.Protected++
		} else {
			result.Deletable++
		}
	}
	if err = rows.Err(); err != nil {
		return LogSelection{}, nil, err
	}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	if err = encoder.Encode([]string{"aswired-log-selection-v1", collection, stamp(from), stamp(to)}); err != nil {
		return LogSelection{}, nil, err
	}
	if err = encoder.Encode(entries); err != nil {
		return LogSelection{}, nil, err
	}
	result.Fingerprint = hex.EncodeToString(hash.Sum(nil))
	return result, entries, nil
}

func (s *Store) logSelectionTransaction(ctx context.Context, deleting bool) (*sql.Tx, error) {
	var options *sql.TxOptions
	if s.driver == "pgx" {
		options = &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: !deleting}
	}
	tx, err := s.db.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	if deleting && s.driver == "sqlite" {
		if _, err = tx.ExecContext(ctx, `UPDATE tasks SET status=status WHERE 1=0`); err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	return tx, nil
}

func (s *Store) PreviewLogSelection(ctx context.Context, collection string, from, to, now time.Time) (LogSelection, error) {
	tx, err := s.logSelectionTransaction(ctx, false)
	if err != nil {
		return LogSelection{}, err
	}
	defer tx.Rollback()
	result, _, err := s.logSelectionTx(ctx, tx, collection, from, to, now, false)
	return result, err
}

func (s *Store) DeleteLogSelection(ctx context.Context, collection string, from, to, now time.Time, fingerprint string, reason func(Task) string) (selection LogSelection, err error) {
	defer func() {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && (pg.Code == "40001" || pg.Code == "40P01") {
			err = ErrLogPreviewChanged
		}
	}()
	tx, err := s.logSelectionTransaction(ctx, true)
	if err != nil {
		return selection, err
	}
	defer tx.Rollback()
	selection, entries, err := s.logSelectionTx(ctx, tx, collection, from, to, now, true)
	if err != nil {
		return selection, err
	}
	if len(fingerprint) != 64 || subtle.ConstantTimeCompare([]byte(selection.Fingerprint), []byte(fingerprint)) != 1 {
		return selection, ErrLogPreviewChanged
	}
	for _, entry := range entries {
		if entry.Protected {
			continue
		}
		if collection == "tasks" {
			retirement := ""
			if reason != nil {
				retirement = reason(entry.task)
			}
			err = s.clearTaskLogTx(ctx, tx, entry.task, now, retirement)
		} else {
			var changed sql.Result
			changed, err = tx.ExecContext(ctx, s.bind(`DELETE FROM audit_events WHERE id=? AND created_at=?`), entry.ID, entry.CreatedAt)
			if err == nil {
				var count int64
				count, err = changed.RowsAffected()
				if err == nil && count != 1 {
					err = ErrConflict
				}
			}
		}
		if errors.Is(err, ErrConflict) {
			err = ErrLogPreviewChanged
		}
		if err != nil {
			return selection, err
		}
	}
	return selection, tx.Commit()
}
