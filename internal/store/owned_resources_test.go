package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOwnedQuotaConcurrentAndRollback(t *testing.T) {
	s, path := testStore(t)
	second, e := Open(Config{Driver: "sqlite", DSN: path})
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	ctx := context.Background()
	if e = s.CreateUser(ctx, User{ID: "u", Username: "u", PasswordHash: "hash", Role: "user"}); e != nil {
		t.Fatal(e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db := s
			if i%2 == 1 {
				db = second
			}
			_, err := db.CompareAndSaveOwnedResources(ctx, "u", map[string]int{"nodes": 3}, []Record{{Collection: "nodes", ID: fmt.Sprint(i), OwnerID: "u", Data: map[string]any{}}})
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrInvalid) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 3 {
		t.Fatalf("created %d", successes.Load())
	}
	_, e = s.CompareAndSaveOwnedResources(ctx, "u", map[string]int{"nodes": 3, "sources": 1}, []Record{{Collection: "sources", ID: "s", OwnerID: "u", Data: map[string]any{}}, {Collection: "nodes", ID: "excess", OwnerID: "u", Data: map[string]any{}}})
	if !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e = s.GetRecord(ctx, "sources", "s"); !errors.Is(e, ErrNotFound) {
		t.Fatal("partial batch", e)
	}
	foreign, _ := s.SaveRecord(ctx, Record{Collection: "nodes", ID: "foreign", OwnerID: "other", Data: map[string]any{}})
	foreign.OwnerID = "u"
	if _, e = s.CompareAndSaveOwnedResources(ctx, "u", map[string]int{"nodes": -1}, []Record{foreign}); !errors.Is(e, ErrInvalid) {
		t.Fatal("ownership transfer accepted", e)
	}
}
func TestMemberAtomicAndLastAdministrator(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	u := User{ID: "admin", Username: "admin", PasswordHash: "old", Role: "admin"}
	if e := s.InitializeAdmin(ctx, u); e != nil {
		t.Fatal(e)
	}
	u, _ = s.UserByID(ctx, u.ID)
	r, _ := s.SaveRecord(ctx, Record{Collection: "members", ID: u.ID, Data: map[string]any{"name": "old"}})
	u.PasswordHash = "changed"
	bad := r
	bad.Version = 0
	if _, e := s.SaveMemberRecord(ctx, u, bad, true); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	fresh, _ := s.UserByID(ctx, u.ID)
	if fresh.PasswordHash != "old" {
		t.Fatal("partial identity update")
	}
	u.Role = "user"
	if _, e := s.SaveMemberRecord(ctx, u, r, true); !errors.Is(e, ErrInvalid) {
		t.Fatal("last admin demoted", e)
	}
	u.Role = "admin"
	if _, e := s.SaveMemberRecord(ctx, u, r, true); e != nil {
		t.Fatal(e)
	}
	fresh, _ = s.UserByID(ctx, u.ID)
	if fresh.PasswordHash != "changed" || fresh.TokenVersion != 1 {
		t.Fatal(fresh)
	}
}

func TestDeleteMemberRetainsOneAdminAndCleansOwnedRecords(t *testing.T) {
	s, path := testStore(t)
	ctx := context.Background()
	if e := s.InitializeAdmin(ctx, User{ID: "a", Username: "a", Role: "admin", PasswordHash: "hash"}); e != nil {
		t.Fatal(e)
	}
	if e := s.CreateUser(ctx, User{ID: "b", Username: "b", Role: "admin", PasswordHash: "hash"}); e != nil {
		t.Fatal(e)
	}
	second, e := Open(Config{Driver: "sqlite", DSN: path})
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	var wg sync.WaitGroup
	var deleted atomic.Int32
	for i, id := range []string{"a", "b"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			db := s
			if i == 1 {
				db = second
			}
			err := db.DeleteMember(ctx, id)
			if err == nil {
				deleted.Add(1)
			} else if !errors.Is(err, ErrInvalid) {
				t.Error(err)
			}
		}(i, id)
	}
	wg.Wait()
	if deleted.Load() != 1 {
		t.Fatal("deleted admins", deleted.Load())
	}
	if e = s.CreateUser(ctx, User{ID: "u", Username: "u", Role: "user", PasswordHash: "hash"}); e != nil {
		t.Fatal(e)
	}
	for _, r := range []Record{{Collection: "members", ID: "u", Data: map[string]any{}}, {Collection: "_identity", ID: "u", OwnerID: "u", Data: map[string]any{}}, {Collection: "sources", ID: "src", OwnerID: "u", Data: map[string]any{}}, {Collection: "subscriptions", ID: "sub", OwnerID: "u", Data: map[string]any{"planId": "p"}}} {
		if _, e = s.SaveRecord(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.AppendAudit(ctx, AuditEvent{ID: "audit", ActorID: "u", Action: "history"}); e != nil {
		t.Fatal(e)
	}
	if e = s.DeleteMember(ctx, "u"); e != nil {
		t.Fatal(e)
	}
	if rows, e := s.ListRecords(ctx, "sources", "u"); e != nil || len(rows) != 0 {
		t.Fatal("source orphan", rows, e)
	}
	var count int
	s.db.QueryRow(`SELECT COUNT(*) FROM subscription_bindings WHERE user_id='u'`).Scan(&count)
	if count != 0 {
		t.Fatal("binding orphan")
	}
	events, e := s.ListAudit(ctx, 10)
	if e != nil || len(events) != 1 {
		t.Fatal("history erased", events, e)
	}
}
