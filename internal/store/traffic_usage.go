package store

import (
	"context"
	"database/sql"
)

// TrafficUsage contains the legacy ledger sums, without rounding or regrouping.
type TrafficUsage struct {
	Total, Up, Down float64
}

type trafficUsageEntry struct {
	start, end, revision int64
	latest               sql.NullInt64
	usage                TrafficUsage
}

// SubscriptionUsage reads a coherent ledger snapshot. Only SQLite caches sums;
// PostgreSQL retains the original queries. Authorization decisions are never cached.
func (s *Store) SubscriptionUsage(ctx context.Context, subscriptionID string, start, end int64) (TrafficUsage, error) {
	if s.driver != "sqlite" {
		return s.queryTrafficUsage(ctx, s.db, subscriptionID, start, end)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TrafficUsage{}, err
	}
	defer tx.Rollback()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM traffic_usage_revisions WHERE subscription_id=?),0)`, subscriptionID).Scan(&revision)
	if err != nil {
		return TrafficUsage{}, err
	}
	s.usageMu.Lock()
	entry, ok := s.usageCache[subscriptionID]
	s.usageMu.Unlock()
	// A subscription without a cycle end uses now+100 years. Reuse that moving
	// bound only when neither bound excludes any row; future-dated imports must
	// still obey the exact original half-open interval.
	sameEnd := entry.end == end || !entry.latest.Valid || entry.latest.Int64 < min(entry.end, end)
	if ok && entry.revision == revision && entry.start == start && sameEnd {
		return entry.usage, tx.Commit()
	}
	usage, err := s.queryTrafficUsage(ctx, tx, subscriptionID, start, end)
	if err != nil {
		return TrafficUsage{}, err
	}
	var latest sql.NullInt64
	if err = tx.QueryRowContext(ctx, `SELECT MAX(sampled_at) FROM traffic_ledger WHERE subscription_id=?`, subscriptionID).Scan(&latest); err != nil {
		return TrafficUsage{}, err
	}
	if err = tx.Commit(); err != nil {
		return TrafficUsage{}, err
	}
	s.usageMu.Lock()
	if s.usageCache == nil || len(s.usageCache) >= 1024 {
		s.usageCache = make(map[string]trafficUsageEntry)
	}
	s.usageCache[subscriptionID] = trafficUsageEntry{start: start, end: end, revision: revision, latest: latest, usage: usage}
	s.usageMu.Unlock()
	return usage, nil
}

type trafficQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) queryTrafficUsage(ctx context.Context, q trafficQuerier, subscriptionID string, start, end int64) (usage TrafficUsage, err error) {
	var summed sql.NullFloat64
	err = q.QueryRowContext(ctx, s.Bind(`SELECT SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND sampled_at>=? AND sampled_at<?`), subscriptionID, start, end).Scan(&summed)
	if err != nil {
		return
	}
	usage.Total = summed.Float64
	rows, err := q.QueryContext(ctx, s.Bind(`SELECT direction,SUM(weighted_bytes) FROM traffic_ledger WHERE subscription_id=? AND sampled_at>=? AND sampled_at<? GROUP BY direction`), subscriptionID, start, end)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var direction string
		var value float64
		if err = rows.Scan(&direction, &value); err != nil {
			return
		}
		if direction == "uplink" {
			usage.Up = value
		} else if direction == "downlink" {
			usage.Down = value
		}
	}
	err = rows.Err()
	return
}

// These derived revisions deliberately stay outside logical backups. Ledger
// INSERT/UPDATE/DELETE (including restore and older binaries) invalidate cached
// results in the same transaction. Rollbacks also roll back invalidation.
func createTrafficUsageSchema(ctx context.Context, tx *sql.Tx) error {
	queries := []string{
		// Keeping sampled_at before SQLite's implicit rowid preserves the
		// original subscription/time scan order after filtering one email.
		// Do not append weighted_bytes: that would reorder tied timestamps.
		`CREATE INDEX IF NOT EXISTS traffic_ledger_subscription_email ON traffic_ledger(subscription_id,email,sampled_at)`,
		`CREATE TABLE IF NOT EXISTS traffic_usage_revisions(subscription_id TEXT PRIMARY KEY,revision INTEGER NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS traffic_usage_insert AFTER INSERT ON traffic_ledger BEGIN
		 INSERT INTO traffic_usage_revisions(subscription_id,revision) VALUES(NEW.subscription_id,1)
		 ON CONFLICT(subscription_id) DO UPDATE SET revision=revision+1; END`,
		`CREATE TRIGGER IF NOT EXISTS traffic_usage_delete AFTER DELETE ON traffic_ledger BEGIN
		 INSERT INTO traffic_usage_revisions(subscription_id,revision) VALUES(OLD.subscription_id,1)
		 ON CONFLICT(subscription_id) DO UPDATE SET revision=revision+1; END`,
		`CREATE TRIGGER IF NOT EXISTS traffic_usage_update AFTER UPDATE ON traffic_ledger BEGIN
		 INSERT INTO traffic_usage_revisions(subscription_id,revision) VALUES(OLD.subscription_id,1)
		 ON CONFLICT(subscription_id) DO UPDATE SET revision=revision+1;
		 INSERT INTO traffic_usage_revisions(subscription_id,revision) VALUES(NEW.subscription_id,1)
		 ON CONFLICT(subscription_id) DO UPDATE SET revision=revision+1; END`,
	}
	for _, q := range queries {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
