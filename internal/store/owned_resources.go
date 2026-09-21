package store

import (
	"context"
	"errors"
	"fmt"
)

func (s *Store) CompareAndSaveOwnedResources(ctx context.Context, ownerID string, quotas map[string]int, records []Record) ([]Record, error) {
	if ownerID == "" {
		return nil, ErrInvalid
	}
	if len(records) == 0 {
		return []Record{}, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if s.driver == "sqlite" {
		if _, err = tx.ExecContext(ctx, `UPDATE records SET version=version WHERE 1=0`); err != nil {
			return nil, translate(err)
		}
	}
	query := `SELECT id FROM users WHERE id=?`
	if s.driver == "postgres" {
		query += ` FOR UPDATE`
	}
	var id string
	if err = tx.QueryRowContext(ctx, s.bind(query), ownerID).Scan(&id); err != nil {
		return nil, translate(err)
	}
	seen := map[string]bool{}
	added := map[string]int{}
	for _, r := range records {
		if r.OwnerID != ownerID || (r.Collection != "nodes" && r.Collection != "sources") {
			return nil, ErrInvalid
		}
		key := r.Collection + "\x00" + r.ID
		if seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		old, e := s.scanRecord(tx.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection=? AND id=?`), r.Collection, r.ID))
		if errors.Is(e, ErrNotFound) {
			if r.Version != 0 {
				return nil, ErrConflict
			}
			added[r.Collection]++
		} else if e != nil {
			return nil, e
		} else if old.OwnerID != ownerID {
			return nil, ErrInvalid
		} else if old.Version != r.Version {
			return nil, ErrConflict
		}
	}
	for collection, count := range added {
		quota, ok := quotas[collection]
		if !ok {
			return nil, fmt.Errorf("%w: missing %s quota", ErrInvalid, collection)
		}
		if quota < 0 {
			continue
		}
		var existing int
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM records WHERE collection=? AND owner_id=?`), collection, ownerID).Scan(&existing); err != nil {
			return nil, err
		}
		if count > quota-existing {
			return nil, fmt.Errorf("%w: %s quota exceeded (%d)", ErrInvalid, collection, quota)
		}
	}
	out := make([]Record, 0, len(records))
	for _, r := range records {
		saved, e := s.saveRecordTx(ctx, tx, r)
		if e != nil {
			return nil, e
		}
		out = append(out, saved)
	}
	if err = tx.Commit(); err != nil {
		return nil, translate(err)
	}
	return out, nil
}
