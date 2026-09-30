package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// TrafficPoolUsage is one consistent ledger and membership snapshot. Retired
// subscriptions remain in the pool's private window map until its next reset.
type TrafficPoolUsage struct {
	TrafficUsage
	MemberCount          int
	CycleStart, CycleEnd string
}

func (s *Store) TrafficPoolUsage(ctx context.Context, planID string, end int64) (TrafficPoolUsage, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		return TrafficPoolUsage{}, err
	}
	defer tx.Rollback()
	pool, err := s.scanRecord(tx.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection='_trafficPools' AND id=?`), planID))
	if err != nil {
		return TrafficPoolUsage{}, err
	}
	cycleStart, _ := pool.Data["cycleStart"].(string)
	cycleEnd, _ := pool.Data["cycleEnd"].(string)
	if cycleEnd != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, cycleEnd)
		if parseErr != nil {
			return TrafficPoolUsage{}, parseErr
		}
		end = parsed.UnixMilli()
	}
	members, validMembers := pool.Data["members"].(map[string]any)
	if !validMembers {
		return TrafficPoolUsage{}, errors.New("invalid traffic pool membership")
	}
	ids := make([]string, 0, len(members))
	for id := range members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var result TrafficPoolUsage
	result.CycleStart, result.CycleEnd = cycleStart, cycleEnd
	var sums ledgerSums
	entries := map[string]trafficUsageEntry{}
	for _, id := range ids {
		startText, _ := members[id].(string)
		start, err := time.Parse(time.RFC3339Nano, startText)
		if err != nil {
			return TrafficPoolUsage{}, fmt.Errorf("invalid traffic pool window: %w", err)
		}
		var usage TrafficUsage
		if s.driver == "sqlite" {
			// Independent from the personal-cycle cache: conversion can retain
			// a different start, and alternating the two must not force rebuilds.
			key := "\x00pool/" + planID + "/" + id
			s.usageMu.Lock()
			previous, cached := s.usageCache[key]
			s.usageMu.Unlock()
			entry, readErr := s.readLedgerUsageTx(ctx, tx, id, nil, start.UnixMilli(), end, previous, cached)
			if readErr != nil {
				return TrafficPoolUsage{}, readErr
			}
			usage, entries[key] = entry.usage, entry
		} else {
			usage, err = s.queryTrafficUsage(ctx, tx, id, start.UnixMilli(), end)
			if err != nil {
				return TrafficPoolUsage{}, err
			}
		}
		// A pool is explicitly the sum of its members' established billable
		// totals. Preserve each member's existing SQLite summation contract.
		sums.total.add(usage.Total)
		sums.up.add(usage.Up)
		sums.down.add(usage.Down)
	}
	if err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM subscription_bindings WHERE plan_id=?`), planID).Scan(&result.MemberCount); err != nil {
		return TrafficPoolUsage{}, err
	}
	if err = tx.Commit(); err != nil {
		return TrafficPoolUsage{}, err
	}
	result.TrafficUsage = sums.usage()
	s.usageMu.Lock()
	if s.usageCache == nil {
		s.usageCache = map[string]trafficUsageEntry{}
	}
	for key, entry := range entries {
		if _, exists := s.usageCache[key]; !exists && len(s.usageCache) >= 2048 {
			for old := range s.usageCache {
				delete(s.usageCache, old)
				break
			}
		}
		s.usageCache[key] = entry
	}
	s.usageMu.Unlock()
	return result, nil
}

// A conversion and its opening windows commit together. Reading subscription
// bindings here (rather than before the transaction) also covers racing joins.
func (s *Store) SaveTrafficPool(ctx context.Context, pool Record, initial, reset bool, plan *Record) (Record, Record, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, Record{}, err
	}
	defer tx.Rollback()
	if s.driver == "sqlite" {
		if _, err = tx.ExecContext(ctx, `UPDATE records SET version=version WHERE 1=0`); err != nil {
			return Record{}, Record{}, err
		}
	} else {
		// Every shared membership creation locks the plan before touching its
		// pool record, serializing conversion, resets and concurrent joins.
		if _, err = tx.ExecContext(ctx, s.bind(`SELECT id FROM records WHERE collection='plans' AND id=? FOR UPDATE`), pool.ID); err != nil {
			return Record{}, Record{}, err
		}
	}
	if initial || reset {
		rows, readErr := tx.QueryContext(ctx, s.bind(`SELECT r.collection,r.id,r.owner_id,r.data,r.version,r.created_at,r.updated_at FROM records r JOIN subscription_bindings b ON r.collection='subscriptions' AND r.id=b.subscription_id WHERE b.plan_id=? ORDER BY r.id`), pool.ID)
		if readErr != nil {
			return Record{}, Record{}, readErr
		}
		members := map[string]any{}
		for rows.Next() {
			sub, scanErr := s.scanRecord(rows)
			if scanErr != nil {
				rows.Close()
				return Record{}, Record{}, scanErr
			}
			start, _ := pool.Data["cycleStart"].(string)
			if initial {
				start, _ = sub.Data["cycleStart"].(string)
				if start == "" {
					start = sub.CreatedAt.Format(time.RFC3339Nano)
				}
			}
			members[sub.ID] = start
		}
		readErr = rows.Err()
		rows.Close()
		if readErr != nil {
			return Record{}, Record{}, readErr
		}
		pool.Data["members"] = members
	}
	savedPool, err := s.saveRecordTx(ctx, tx, pool)
	if err != nil {
		return Record{}, Record{}, err
	}
	var savedPlan Record
	if plan != nil {
		savedPlan, err = s.saveRecordTx(ctx, tx, *plan)
		if err != nil {
			return Record{}, Record{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Record{}, Record{}, err
	}
	return savedPool, savedPlan, nil
}

// Register in the same transaction as creation, including membership redemption
// and other non-HTTP creation paths. The pool has no OwnerID so deleting a user
// cannot erase that user's already-consumed shared traffic.
func (s *Store) registerTrafficPoolMemberTx(ctx context.Context, tx *sql.Tx, sub Record) error {
	planID, _ := sub.Data["planId"].(string)
	if s.driver == "pgx" {
		if _, err := tx.ExecContext(ctx, s.bind(`SELECT id FROM records WHERE collection='plans' AND id=? FOR UPDATE`), planID); err != nil {
			return err
		}
	}
	pool, err := s.scanRecord(tx.QueryRowContext(ctx, s.bind(`SELECT `+recordColumns+` FROM records WHERE collection='_trafficPools' AND id=?`), planID))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	members, validMembers := pool.Data["members"].(map[string]any)
	if !validMembers {
		return errors.New("invalid traffic pool membership")
	}
	if _, exists := members[sub.ID]; exists {
		return nil
	}
	start, _ := sub.Data["cycleStart"].(string)
	if start == "" {
		start = time.Now().UTC().Format(time.RFC3339Nano)
	}
	members[sub.ID], pool.Data["members"] = start, members
	_, err = s.saveRecordTx(ctx, tx, pool)
	return err
}
