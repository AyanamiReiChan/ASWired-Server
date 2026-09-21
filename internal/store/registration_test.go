package store

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func invitationFixture(t *testing.T, s *Store, id, status string, expiry time.Time) {
	t.Helper()
	if _, err := s.SaveRecord(context.Background(), Record{Collection: RegistrationInvites, ID: id, Data: map[string]any{"status": status, "expiresAt": expiry.UTC().Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
}
func invitedUser(id string) User {
	return User{ID: id, Username: id, PasswordHash: "test-hash", Role: "user", TokenVersion: 1}
}

func TestRegistrationInvitationAtomicAcrossConnections(t *testing.T) {
	s, path := testStore(t)
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	invitationFixture(t, s, "single", "active", time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := range 12 {
		wg.Go(func() {
			db := s
			if i%2 == 1 {
				db = other
			}
			if db.RegisterInvitedUser(context.Background(), "single", invitedUser(fmt.Sprintf("user-%d", i))) == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	users, err := s.ListUsers(context.Background())
	if err != nil || successes.Load() != 1 || len(users) != 1 {
		t.Fatalf("successes=%d users=%d err=%v", successes.Load(), len(users), err)
	}
	member, err := s.GetRecord(context.Background(), "members", users[0].ID)
	if err != nil || member.OwnerID != users[0].ID {
		t.Fatal("member missing", err)
	}
	invite, _ := s.GetRecord(context.Background(), RegistrationInvites, "single")
	if invite.Data["usedBy"] != users[0].ID || invite.Data["status"] != "used" {
		t.Fatal("consumption mismatch")
	}
}
func TestRegistrationRollbackAndInvalidInvitations(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	first := invitedUser("existing")
	if err := s.CreateUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	invitationFixture(t, s, "duplicate", "active", time.Now().Add(time.Hour))
	duplicate := invitedUser("new-id")
	duplicate.Username = "EXISTING"
	if s.RegisterInvitedUser(ctx, "duplicate", duplicate) == nil {
		t.Fatal("duplicate username accepted")
	}
	if err := s.RegisterInvitedUser(ctx, "duplicate", invitedUser("valid-next")); err != nil {
		t.Fatal("duplicate failure consumed invite", err)
	}
	for _, tc := range []struct {
		id, status string
		expiry     time.Time
	}{{"expired", "active", time.Now().Add(-time.Second)}, {"revoked", "revoked", time.Now().Add(time.Hour)}, {"used", "used", time.Now().Add(time.Hour)}} {
		invitationFixture(t, s, tc.id, tc.status, tc.expiry)
		if s.RegisterInvitedUser(ctx, tc.id, invitedUser(tc.id)) == nil {
			t.Fatal("accepted", tc.id)
		}
	}
	invitationFixture(t, s, "admin", "active", time.Now().Add(time.Hour))
	admin := invitedUser("escalation")
	admin.Role = "admin"
	if s.RegisterInvitedUser(ctx, "admin", admin) == nil {
		t.Fatal("accepted admin registration")
	}
	users, _ := s.ListUsers(ctx)
	if len(users) != 2 {
		t.Fatal("failed registrations wrote accounts")
	}
}
