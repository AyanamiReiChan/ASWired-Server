package store

import (
	"context"
	"database/sql"
)

const nodeTrafficUsageCacheLimit = 1024

type nodeTrafficUsageKey struct {
	subscriptionID, email string
}

type nodeTrafficUsageEntry struct {
	start, end, revision int64
	latest               sql.NullInt64
	usage                float64
}

// NodeTrafficUsage reads the original weighted ledger sum for one subscription
// and Xray email. Only SQLite caches results, using the same transactional
// revision invalidation as SubscriptionUsage. Quotas and permissions stay live.
func (s *Store) NodeTrafficUsage(ctx context.Context, subscriptionID, email string, start, end int64) (float64, error) {
	if s.driver != "sqlite" {
		return s.queryNodeTrafficUsage(ctx, s.db, subscriptionID, email, start, end)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM traffic_usage_revisions WHERE subscription_id=?),0)`, subscriptionID).Scan(&revision); err != nil {
		return 0, err
	}
	key := nodeTrafficUsageKey{subscriptionID: subscriptionID, email: email}
	s.usageMu.Lock()
	entry, ok := s.nodeUsageCache[key]
	s.usageMu.Unlock()
	// No-reset subscriptions have a moving now+100-year end. It can be
	// reused only when both bounds include every possible row for this pair.
	sameEnd := entry.end == end || !entry.latest.Valid || entry.latest.Int64 < min(entry.end, end)
	if ok && entry.revision == revision && entry.start == start && sameEnd {
		return entry.usage, tx.Commit()
	}
	usage, err := s.queryNodeTrafficUsage(ctx, tx, subscriptionID, email, start, end)
	if err != nil {
		return 0, err
	}
	var latest sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT MAX(sampled_at) FROM traffic_ledger WHERE subscription_id=? AND email=?`, subscriptionID, email).Scan(&latest); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	s.usageMu.Lock()
	if s.nodeUsageCache == nil {
		s.nodeUsageCache = make(map[nodeTrafficUsageKey]nodeTrafficUsageEntry)
	}
	if _, exists := s.nodeUsageCache[key]; !exists && len(s.nodeUsageCache) >= nodeTrafficUsageCacheLimit {
		// Evict one entry rather than discard every warm node when full.
		for oldKey := range s.nodeUsageCache {
			delete(s.nodeUsageCache, oldKey)
			break
		}
	}
	s.nodeUsageCache[key] = nodeTrafficUsageEntry{start: start, end: end, revision: revision, latest: latest, usage: usage}
	s.usageMu.Unlock()
	return usage, nil
}

func (s *Store) queryNodeTrafficUsage(ctx context.Context, q trafficQuerier, subscriptionID, email string, start, end int64) (float64, error) {
	var summed sql.NullFloat64
	err := q.QueryRowContext(ctx, s.Bind(`SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND email=? AND sampled_at>=? AND sampled_at<?`), subscriptionID, email, start, end).Scan(&summed)
	return summed.Float64, err
}
