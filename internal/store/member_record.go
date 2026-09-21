package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Store) SaveMemberRecord(ctx context.Context, u User, r Record, exists bool) (Record, error) {
	if err := validateUser(u); err != nil {
		return Record{}, err
	}
	if r.Collection != "members" || r.ID != u.ID {
		return Record{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()

	if _, err = tx.ExecContext(ctx, `UPDATE settings SET updated_at=updated_at WHERE key='_internal.initialized'`); err != nil {
		return Record{}, err
	}
	if !exists {
		if r.Version != 0 {
			return Record{}, ErrConflict
		}
		if err = s.insertUser(ctx, tx, u); err != nil {
			return Record{}, err
		}
	} else {
		old, e := scanUser(tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM users WHERE id=?`), u.ID))
		if e != nil {
			return Record{}, e
		}
		if u.UpdatedAt.IsZero() || !u.UpdatedAt.Equal(old.UpdatedAt) {
			return Record{}, ErrConflict
		}
		if old.Role == "admin" && !old.Disabled && (u.Role != "admin" || u.Disabled) {
			var count int
			if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&count); e != nil {
				return Record{}, e
			}
			if count <= 1 {
				return Record{}, fmt.Errorf("%w: cannot disable or demote the last administrator", ErrInvalid)
			}
		}
		version := old.TokenVersion
		if u.TokenVersion > version {
			version = u.TokenVersion
		}
		if old.PasswordHash != u.PasswordHash || old.Role != u.Role || old.Disabled != u.Disabled {
			if version <= old.TokenVersion {
				version = old.TokenVersion + 1
			}
		}
		disabled := 0
		if u.Disabled {
			disabled = 1
		}
		result, e := tx.ExecContext(ctx, s.bind(`UPDATE users SET username=?,username_key=?,password_hash=?,role=?,disabled=?,token_version=?,updated_at=? WHERE id=? AND updated_at=?`), strings.TrimSpace(u.Username), strings.ToLower(strings.TrimSpace(u.Username)), u.PasswordHash, u.Role, disabled, version, stamp(time.Now()), u.ID, stamp(old.UpdatedAt))
		if e != nil {
			return Record{}, translate(e)
		}
		n, e := result.RowsAffected()
		if e != nil {
			return Record{}, e
		}
		if n != 1 {
			return Record{}, ErrConflict
		}
	}
	saved, err := s.saveRecordTx(ctx, tx, r)
	if err != nil {
		return Record{}, err
	}
	if err = tx.Commit(); err != nil {
		return Record{}, translate(err)
	}
	return saved, nil
}
