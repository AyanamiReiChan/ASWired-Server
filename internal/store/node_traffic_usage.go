package store

import (
	"context"
	"database/sql"
)

const nodeTrafficUsageCacheLimit = 1024

type nodeTrafficUsageKey struct {
	subscriptionID, email string
}

type nodeTrafficUsageEntry = trafficUsageEntry

// NodeTrafficUsage reads the original weighted ledger sum for one subscription
// and Xray email. Only SQLite caches results, using the same transactional
// revision invalidation as SubscriptionUsage. Quotas and permissions stay live.
func (s *Store) NodeTrafficUsage(ctx context.Context, subscriptionID, email string, start, end int64) (float64, error) {
	if s.driver != "sqlite" {
		return s.queryNodeTrafficUsage(ctx, s.db, subscriptionID, email, start, end)
	}
	key := nodeTrafficUsageKey{subscriptionID: subscriptionID, email: email}
	s.usageMu.Lock()
	entry, ok := s.nodeUsageCache[key]
	s.usageMu.Unlock()
	entry, err := s.readLedgerUsage(ctx, subscriptionID, &email, start, end, entry, ok)
	if err != nil {
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
	s.nodeUsageCache[key] = entry
	s.usageMu.Unlock()
	return entry.usage.Total, nil
}

func (s *Store) queryNodeTrafficUsage(ctx context.Context, q trafficQuerier, subscriptionID, email string, start, end int64) (float64, error) {
	var summed sql.NullFloat64
	err := q.QueryRowContext(ctx, s.Bind(`SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND email=? AND sampled_at>=? AND sampled_at<?`), subscriptionID, email, start, end).Scan(&summed)
	return summed.Float64, err
}
