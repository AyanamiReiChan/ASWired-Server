package store

import (
	"context"
	"time"
)

const RegistrationInvites = "_registrationInvites"

// RegisterInvitedUser consumes an invitation and creates both account and member
// atomically. A failed insert (including duplicate username) keeps it usable.
func (s *Store) RegisterInvitedUser(ctx context.Context, inviteID string, u User) error {
	if validateUser(u) != nil || u.Role != "user" || u.Disabled {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.driver == "sqlite" {
		if _, err = tx.ExecContext(ctx, `UPDATE records SET version=version WHERE 1=0`); err != nil {
			return translate(err)
		}
	}
	invite, err := s.scanRecord(tx.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection=? AND id=?`), RegistrationInvites, inviteID))
	if err != nil {
		return err
	}
	status, _ := invite.Data["status"].(string)
	expires, _ := invite.Data["expiresAt"].(string)
	expiry, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || status != "active" || !time.Now().Before(expiry) {
		return ErrInvalid
	}
	invite.Data["status"] = "used"
	invite.Data["usedBy"] = u.ID
	invite.Data["usedUsername"] = u.Username
	invite.Data["usedAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = s.saveRecordTx(ctx, tx, invite); err != nil {
		return err
	}
	if err = s.insertUser(ctx, tx, u); err != nil {
		return err
	}
	member := Record{Collection: "members", ID: u.ID, OwnerID: u.ID, Data: map[string]any{"name": u.Username, "username": u.Username, "role": "成员", "status": "正常", "used": 0, "limit": 0}}
	if _, err = s.saveRecordTx(ctx, tx, member); err != nil {
		return err
	}
	return translate(tx.Commit())
}
