package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const userColumns = `id,username,password_hash,role,disabled,token_version,created_at,updated_at`

func validateUser(u User) error {
	if strings.TrimSpace(u.ID) == "" || strings.TrimSpace(u.Username) == "" || len(u.Username) > 128 || u.PasswordHash == "" || (u.Role != "admin" && u.Role != "user") || u.TokenVersion < 0 {
		return ErrInvalid
	}
	return nil
}

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var disabled int
	var created, updated string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &disabled, &u.TokenVersion, &created, &updated)
	u.Disabled = disabled != 0
	u.CreatedAt = parseStamp(created)
	u.UpdatedAt = parseStamp(updated)
	return u, translate(err)
}

func (s *Store) insertUser(ctx context.Context, tx *sql.Tx, u User) error {
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	disabled := 0
	if u.Disabled {
		disabled = 1
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO users(id,username,username_key,password_hash,role,disabled,token_version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`), u.ID, strings.TrimSpace(u.Username), strings.ToLower(strings.TrimSpace(u.Username)), u.PasswordHash, u.Role, disabled, u.TokenVersion, stamp(u.CreatedAt), stamp(u.UpdatedAt))
	return translate(err)
}

func (s *Store) InitializeAdmin(ctx context.Context, u User) error {
	if err := validateUser(u); err != nil {
		return err
	}
	if u.Role != "admin" || u.Disabled {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, s.bind(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING`), "_internal.initialized", "true", stamp(time.Now()))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInitialized
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrInitialized
	}
	if err := s.insertUser(ctx, tx, u); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM users WHERE username_key=?`), strings.ToLower(strings.TrimSpace(username))))
}

func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM users WHERE id=?`), id))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, u User) error {
	if err := validateUser(u); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.insertUser(ctx, tx, u); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateUser(ctx context.Context, u User) error {
	if err := validateUser(u); err != nil {
		return err
	}
	disabled := 0
	if u.Disabled {
		disabled = 1
	}

	query := `UPDATE users SET username=?,username_key=?,token_version=CASE WHEN password_hash<>? OR role<>? OR disabled<>? THEN CASE WHEN token_version>=? THEN token_version+1 ELSE ? END ELSE CASE WHEN token_version>? THEN token_version ELSE ? END END,password_hash=?,role=?,disabled=?,updated_at=? WHERE id=?`
	args := []any{strings.TrimSpace(u.Username), strings.ToLower(strings.TrimSpace(u.Username)), u.PasswordHash, u.Role, disabled, u.TokenVersion, u.TokenVersion, u.TokenVersion, u.TokenVersion, u.PasswordHash, u.Role, disabled, stamp(time.Now()), u.ID}
	if !u.UpdatedAt.IsZero() {
		query += ` AND updated_at=?`
		args = append(args, stamp(u.UpdatedAt))
	}
	result, err := s.db.ExecContext(ctx, s.bind(query), args...)
	if err != nil {
		return translate(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.UserByID(ctx, u.ID); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM users WHERE id=?`), id)
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
	return nil
}
