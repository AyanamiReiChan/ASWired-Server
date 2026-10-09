package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
)

// MemberTrafficWindow is a half-open personal subscription accounting window.
type MemberTrafficWindow struct {
	SubscriptionID string
	Start, End     int64
}

// MemberTrafficGroup keeps the exact ledger identity private to the backend.
// Historical factors are already included in Weighted; never recalculate them
// using today's plan or inbound configuration.
type MemberTrafficGroup struct {
	SubscriptionID, ServerID, Email string
	Weighted, Raw                   TrafficUsage
	First, Last                     int64
	Gap                             bool
}

const memberTrafficSelect = `SELECT subscription_id,server_id,email,
 SUM(weighted_bytes),SUM(CASE WHEN direction='uplink' THEN weighted_bytes ELSE 0 END),SUM(CASE WHEN direction='downlink' THEN weighted_bytes ELSE 0 END),
 SUM(CAST(raw_bytes AS DOUBLE PRECISION)),SUM(CASE WHEN direction='uplink' THEN CAST(raw_bytes AS DOUBLE PRECISION) ELSE 0 END),SUM(CASE WHEN direction='downlink' THEN CAST(raw_bytes AS DOUBLE PRECISION) ELSE 0 END),
 MIN(sampled_at),MAX(sampled_at),MAX(gap) FROM traffic_ledger WHERE owner_id=? AND sampled_at>=? AND sampled_at<?`

func memberTrafficQuery(ownerID string, start, end int64, windows []MemberTrafficWindow) (string, []any) {
	query := memberTrafficSelect
	args := []any{ownerID, start, end}
	if windows != nil {
		parts := make([]string, 0, len(windows))
		for _, window := range windows {
			parts = append(parts, `(subscription_id=? AND sampled_at>=? AND sampled_at<?)`)
			args = append(args, window.SubscriptionID, window.Start, window.End)
		}
		query += ` AND (` + strings.Join(parts, ` OR `) + `)`
	}
	return query + ` GROUP BY subscription_id,server_id,email ORDER BY subscription_id,server_id,email`, args
}

// MemberTrafficDistribution is an on-demand read. It uses the existing
// owner/time index, returns aggregates instead of materializing ledger rows,
// and neither updates nor evicts the quota caches used by agent reports.
// nil windows includes retired subscriptions; an empty slice selects none.
func (s *Store) MemberTrafficDistribution(ctx context.Context, ownerID string, start, end int64, windows []MemberTrafficWindow) ([]MemberTrafficGroup, error) {
	result := make([]MemberTrafficGroup, 0)
	if ownerID == "" || end <= start || (windows != nil && len(windows) == 0) {
		return result, nil
	}
	// A subscription must occur only once, so batched predicates cannot count
	// the same ledger row twice. This is also a guard for future callers.
	seen := map[string]bool{}
	for _, window := range windows {
		if window.SubscriptionID == "" || seen[window.SubscriptionID] || window.End <= window.Start {
			return nil, ErrInvalid
		}
		seen[window.SubscriptionID] = true
	}
	options := &sql.TxOptions{ReadOnly: true}
	if s.driver == "pgx" {
		options.Isolation = sql.LevelRepeatableRead
	}
	tx, err := s.db.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Bound parameters and expression depth even for accounts with hundreds of
	// subscriptions. Normally this is a single GROUP BY query, not one per node.
	for offset := 0; ; {
		batch := windows
		if windows != nil {
			limit := min(offset+128, len(windows))
			batch = windows[offset:limit]
			offset = limit
		}
		query, args := memberTrafficQuery(ownerID, start, end, batch)
		rows, err := tx.QueryContext(ctx, s.Bind(query), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var group MemberTrafficGroup
			var gap int
			if err := rows.Scan(&group.SubscriptionID, &group.ServerID, &group.Email,
				&group.Weighted.Total, &group.Weighted.Up, &group.Weighted.Down,
				&group.Raw.Total, &group.Raw.Up, &group.Raw.Down, &group.First, &group.Last, &gap); err != nil {
				rows.Close()
				return nil, err
			}
			for _, value := range []float64{group.Weighted.Total, group.Weighted.Up, group.Weighted.Down, group.Raw.Total, group.Raw.Up, group.Raw.Down} {
				if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
					rows.Close()
					return nil, fmt.Errorf("invalid member traffic aggregate")
				}
			}
			group.Gap = gap != 0
			result = append(result, group)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if windows == nil || offset == len(windows) {
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
