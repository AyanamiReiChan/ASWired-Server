package store

import "context"

// ConsumeRecord is a compare-and-delete: only one redeemer can consume a snapshot.
func (s *Store) ConsumeRecord(ctx context.Context, record Record) error {
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM records WHERE collection=? AND id=? AND version=?`), record.Collection, record.ID, record.Version)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}
