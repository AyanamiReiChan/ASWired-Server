package store

import (
	"context"
	"fmt"
)

func (s *Store) DeleteMember(ctx context.Context, id string) error {
	if id == "" {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE settings SET updated_at=updated_at WHERE key='_internal.initialized'`); err != nil {
		return err
	}
	query := `SELECT ` + userColumns + ` FROM users WHERE id=?`
	if s.driver == "postgres" {
		query += ` FOR UPDATE`
	}
	u, err := scanUser(tx.QueryRowContext(ctx, s.bind(query), id))
	if err != nil {
		return err
	}
	if u.Role == "admin" && !u.Disabled {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&count); err != nil {
			return err
		}
		if count <= 1 {
			return fmt.Errorf("%w: cannot delete the last administrator", ErrInvalid)
		}
	}
	for _, q := range []string{`DELETE FROM subscription_bindings WHERE user_id=?`, `DELETE FROM records WHERE owner_id=?`, `DELETE FROM records WHERE id=? AND collection IN ('members','_identity','_mergedSubscriptions')`, `DELETE FROM users WHERE id=?`} {
		if _, err = tx.ExecContext(ctx, s.bind(q), id); err != nil {
			return translate(err)
		}
	}
	return tx.Commit()
}
