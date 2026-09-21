package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBatchSubscriptionRedemptionIsAtomic(t *testing.T) {
	s, path := testStore(t)
	ctx := context.Background()
	code, err := s.SaveRecord(ctx, Record{Collection: "redeemCodes", ID: "code", Data: map[string]any{"state": "unused"}})
	if err != nil {
		t.Fatal(err)
	}
	sub := Record{Collection: "subscriptions", ID: "sub", OwnerID: "user", Data: map[string]any{"planId": "plan"}}
	code.Data["state"] = "consumed"
	saved, err := s.CompareAndSaveRecords(ctx, []Record{code, sub})
	if err != nil || len(saved) != 2 || saved[0].Version != 2 || saved[1].Version != 1 {
		t.Fatalf("batch result: %v %v", saved, err)
	}
	second, _ := s.SaveRecord(ctx, Record{Collection: "redeemCodes", ID: "second", Data: map[string]any{"state": "unused"}})
	second.Data["state"] = "consumed"
	sub.ID = "duplicate"
	if _, err := s.CompareAndSaveRecords(ctx, []Record{second, sub}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate binding: %v", err)
	}
	untouched, _ := s.GetRecord(ctx, "redeemCodes", "second")
	if untouched.Version != 1 || untouched.Data["state"] != "unused" {
		t.Fatal("failed subscription consumed its code")
	}
	second.Data["state"] = "consumed"
	stale := saved[1]
	stale.Version = 3
	if _, err := s.CompareAndSaveRecords(ctx, []Record{second, stale}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	untouched, _ = s.GetRecord(ctx, "redeemCodes", "second")
	if untouched.Version != 1 {
		t.Fatal("stale transaction partially committed")
	}
	other, err := Open(Config{Driver: "sqlite", DSN: path})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := s
			if i%2 == 1 {
				handle = other
			}
			candidate := Record{Collection: "subscriptions", ID: fmt.Sprintf("concurrent-%d", i), OwnerID: "another", Data: map[string]any{"planId": "plan"}}
			if _, err := handle.CompareAndSaveRecords(ctx, []Record{second, candidate}); err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("concurrent batch: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("redeemed same code %d times", successes.Load())
	}
}
