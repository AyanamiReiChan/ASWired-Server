package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

const recordColumns = `collection,id,owner_id,data,version,created_at,updated_at`

func (s *Store) scanRecord(row interface{ Scan(...any) error }) (Record, error) {
	var r Record
	var raw, created, updated string
	if err := row.Scan(&r.Collection, &r.ID, &r.OwnerID, &raw, &r.Version, &created, &updated); err != nil {
		return r, translate(err)
	}
	if err := s.decodeJSON([]byte(raw), &r.Data); err != nil {
		return r, err
	}
	r.CreatedAt = parseStamp(created)
	r.UpdatedAt = parseStamp(updated)
	return r, nil
}

func (s *Store) ListRecords(ctx context.Context, collection, ownerID string) ([]Record, error) {
	query := `SELECT ` + recordColumns + ` FROM records WHERE collection=?`
	args := []any{collection}
	if ownerID != "" {
		query += ` AND owner_id=?`
		args = append(args, ownerID)
	}
	query += ` ORDER BY created_at,id`
	rows, err := s.db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Record, 0)
	for rows.Next() {
		r, err := s.scanRecord(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) GetRecord(ctx context.Context, collection, id string) (Record, error) {
	return s.scanRecord(s.db.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection=? AND id=?`), collection, id))
}

func (s *Store) SaveRecord(ctx context.Context, r Record) (Record, error) {
	rows, err := s.CompareAndSaveRecords(ctx, []Record{r})
	if err != nil {
		return Record{}, err
	}
	return rows[0], nil
}

func (s *Store) CompareAndSaveRecords(ctx context.Context, records []Record) ([]Record, error) {
	if len(records) == 0 {
		return []Record{}, nil
	}
	seen := make(map[string]bool, len(records))
	for _, r := range records {
		key := r.Collection + "\x00" + r.ID
		if seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if s.driver == "sqlite" {
		if _, err := tx.ExecContext(ctx, `UPDATE records SET version=version WHERE 1=0`); err != nil {
			return nil, translate(err)
		}
	}
	result := make([]Record, 0, len(records))
	for _, r := range records {
		saved, err := s.saveRecordTx(ctx, tx, r)
		if err != nil {
			return nil, err
		}
		result = append(result, saved)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) saveRecordTx(ctx context.Context, tx *sql.Tx, r Record) (Record, error) {
	if strings.TrimSpace(r.Collection) == "" || strings.TrimSpace(r.ID) == "" || r.Data == nil || r.Version < 0 {
		return Record{}, ErrInvalid
	}
	raw, err := s.encodeJSON(r.Data)
	if err != nil {
		return Record{}, err
	}
	if r.Collection == "subscriptions" {
		planID, _ := r.Data["planId"].(string)
		if r.OwnerID == "" || planID == "" {
			return Record{}, ErrInvalid
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO subscription_bindings(subscription_id,user_id,plan_id) VALUES(?,?,?) ON CONFLICT(subscription_id) DO UPDATE SET user_id=excluded.user_id,plan_id=excluded.plan_id`), r.ID, r.OwnerID, planID)
		if err != nil {
			return Record{}, translate(err)
		}
	}
	old, err := s.scanRecord(tx.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection=? AND id=?`), r.Collection, r.ID))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Record{}, err
	}
	r.UpdatedAt = time.Now().UTC()
	if errors.Is(err, ErrNotFound) {
		if r.Version > 0 {
			return Record{}, ErrConflict
		}
		r.CreatedAt = r.UpdatedAt
		r.Version = 1
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO records(collection,id,owner_id,data,version,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`), r.Collection, r.ID, r.OwnerID, string(raw), r.Version, stamp(r.CreatedAt), stamp(r.UpdatedAt))
	} else {
		if r.Version != old.Version {
			return Record{}, ErrConflict
		}
		r.CreatedAt = old.CreatedAt
		r.Version = old.Version + 1
		result, execErr := tx.ExecContext(ctx, s.bind(`UPDATE records SET owner_id=?,data=?,version=?,updated_at=? WHERE collection=? AND id=? AND version=?`), r.OwnerID, string(raw), r.Version, stamp(r.UpdatedAt), r.Collection, r.ID, old.Version)
		err = execErr
		if err == nil {
			n, countErr := result.RowsAffected()
			if countErr != nil {
				return Record{}, countErr
			}
			if n != 1 {
				return Record{}, ErrConflict
			}
		}
	}
	if err != nil {
		return Record{}, translate(err)
	}
	return r, nil
}

func (s *Store) DeleteRecord(ctx context.Context, collection, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if collection == "certificates" {
		for _, reference := range []struct{ collection, id string }{{"_certificateMaterial", id}, {"_operationSchedule", "certificate:" + id}} {
			if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM records WHERE collection=? AND id=?`), reference.collection, reference.id); err != nil {
				return err
			}
		}
	}
	if collection == "subscriptions" {
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM subscription_bindings WHERE subscription_id=?`), id); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM records WHERE collection=? AND id=?`), collection, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}
