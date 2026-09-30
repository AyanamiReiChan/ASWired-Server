package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"
)

// Agents use Unix milliseconds for ledger timestamps. Only a prefix older than this
// window is frozen; the recent tail is replayed in (sampled_at,rowid) order.
// Later historical inserts and every update/delete invalidate that prefix.
const trafficReorderWindow int64 = 60_000

// sqliteRealSum retains the *unfinalized* Kahan-Babuska-Neumaier state used by
// modernc.org/sqlite v1.45.0 (SQLite sumStep/sumFinalize). Combining finalized
// SUMs, or replacing this with plain +=, changes billable floating point bits.
// weighted_bytes has REAL affinity, so normal ledger rows take SQLite's real
// path. Unexpected types and non-finite values use the original SQL instead.
type sqliteRealSum struct{ sum, correction float64 }

func (s *sqliteRealSum) add(value float64) {
	previous := s.sum
	next := previous + value
	if math.Abs(previous) > math.Abs(value) {
		s.correction += previous - next + value
	} else {
		s.correction += value - next + previous
	}
	s.sum = next
}

func (s sqliteRealSum) value() float64 { return s.sum + s.correction }

type ledgerSums struct{ total, up, down sqliteRealSum }

func (s *ledgerSums) add(value float64, direction string) {
	s.total.add(value)
	if direction == "uplink" {
		s.up.add(value)
	} else if direction == "downlink" {
		s.down.add(value)
	}
}

func (s ledgerSums) usage() TrafficUsage {
	return TrafficUsage{Total: s.total.value(), Up: s.up.value(), Down: s.down.value()}
}

func finiteUsage(u TrafficUsage) bool {
	for _, v := range []float64{u.Total, u.Up, u.Down} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}

func sameUsageBits(a, b TrafficUsage) bool {
	return math.Float64bits(a.Total) == math.Float64bits(b.Total) &&
		math.Float64bits(a.Up) == math.Float64bits(b.Up) &&
		math.Float64bits(a.Down) == math.Float64bits(b.Down)
}

func ledgerScope(subscriptionID string, email *string) (string, []any) {
	if email != nil {
		return "subscription_id=? AND email=?", []any{subscriptionID, *email}
	}
	return "subscription_id=?", []any{subscriptionID}
}

func (s *Store) readLedgerUsage(ctx context.Context, subscriptionID string, email *string, start, end int64, previous trafficUsageEntry, cached bool) (trafficUsageEntry, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return trafficUsageEntry{}, err
	}
	defer tx.Rollback()
	entry, err := s.readLedgerUsageTx(ctx, tx, subscriptionID, email, start, end, previous, cached)
	if err != nil {
		return trafficUsageEntry{}, err
	}
	return entry, tx.Commit()
}

func (s *Store) readLedgerUsageTx(ctx context.Context, tx *sql.Tx, subscriptionID string, email *string, start, end int64, previous trafficUsageEntry, cached bool) (trafficUsageEntry, error) {
	scope, scopeEmail := 0, ""
	if email != nil {
		scope, scopeEmail = 1, *email
	}
	entry := trafficUsageEntry{start: start, end: end}
	err := tx.QueryRowContext(ctx, `SELECT revision,mutation,latest FROM traffic_usage_windows WHERE subscription_id=? AND scope=? AND email=?`, subscriptionID, scope, scopeEmail).Scan(&entry.revision, &entry.mutation, &entry.latest)
	if err != nil && err != sql.ErrNoRows {
		return trafficUsageEntry{}, err
	}
	where, scopeArgs := ledgerScope(subscriptionID, email)
	if err == sql.ErrNoRows {
		// Upgrading an existing database does not scan or rewrite its ledger.
		// Metadata is created on the first write; until then read the indexed end.
		if err = tx.QueryRowContext(ctx, `SELECT MAX(sampled_at) FROM traffic_ledger WHERE `+where, scopeArgs...).Scan(&entry.latest); err != nil {
			return trafficUsageEntry{}, err
		}
	}
	// Moving no-reset ends are reusable only if no old row crosses either end.
	// New rows are still read using this request's exact [start,end) interval.
	sameEnd := previous.end == end || !previous.latest.Valid || previous.latest.Int64 < min(previous.end, end)
	compatible := cached && previous.start == start && sameEnd
	if compatible && previous.revision == entry.revision && previous.mutation == entry.mutation {
		previous.end = end
		return previous, nil
	}
	entry.frontier = start
	if entry.latest.Valid && entry.latest.Int64 >= math.MinInt64+trafficReorderWindow {
		entry.frontier = max(start, entry.latest.Int64-trafficReorderWindow)
	}
	from := start
	var sums ledgerSums
	appendOnly := compatible && previous.incremental && previous.mutation == entry.mutation && previous.revision < entry.revision
	if appendOnly {
		from, sums = previous.frontier, previous.prefix
	}
	entry.prefix = sums
	args := append(append([]any{}, scopeArgs...), from, end)
	rows, err := tx.QueryContext(ctx, `SELECT sampled_at,weighted_bytes,direction FROM traffic_ledger WHERE `+where+` AND sampled_at>=? AND sampled_at<? ORDER BY sampled_at,rowid`, args...)
	if err != nil {
		return trafficUsageEntry{}, err
	}
	entry.incremental = true
	for rows.Next() {
		var sampledAt int64
		var raw any
		var direction string
		if err = rows.Scan(&sampledAt, &raw, &direction); err != nil {
			break
		}
		value, real := raw.(float64)
		if !real || math.IsNaN(value) || math.IsInf(value, 0) {
			entry.incremental = false
			break
		}
		sums.add(value, direction)
		if sampledAt < entry.frontier {
			entry.prefix = sums
		}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return trafficUsageEntry{}, err
	}
	entry.usage = sums.usage()
	entry.incremental = entry.incremental && finiteUsage(entry.usage)
	if email != nil {
		entry.usage.Up, entry.usage.Down = 0, 0
	}
	if !appendOnly || !entry.incremental {
		// A cold rebuild certifies the carried state against the unchanged SQL
		// contract. A driver/aggregate change or unusual data fails closed to SQL.
		var legacy TrafficUsage
		if email == nil {
			legacy, err = s.queryTrafficUsage(ctx, tx, subscriptionID, start, end)
		} else {
			legacy.Total, err = s.queryNodeTrafficUsage(ctx, tx, subscriptionID, *email, start, end)
		}
		if err != nil {
			return trafficUsageEntry{}, err
		}
		entry.incremental = entry.incremental && sameUsageBits(entry.usage, legacy)
		entry.usage = legacy
	}
	return entry, nil
}

// Window metadata is derived and intentionally absent from logical backups.
// Triggers cover external connections and old binaries, participate in rollback,
// and invalidate both the old and new scope of moved rows. The original revision
// triggers remain for backward compatibility with an older running controller.
func createTrafficWindowSchema(ctx context.Context, tx *sql.Tx) error {
	queries := []string{`CREATE TABLE IF NOT EXISTS traffic_usage_windows(
	 subscription_id TEXT NOT NULL,scope INTEGER NOT NULL,email TEXT NOT NULL,
	 revision INTEGER NOT NULL,mutation INTEGER NOT NULL,latest INTEGER,
	 PRIMARY KEY(subscription_id,scope,email))`}
	latest := func(alias string, node bool) string {
		filter := "subscription_id=" + alias + ".subscription_id"
		if node {
			filter += " AND email=" + alias + ".email"
		}
		return `(SELECT sampled_at FROM traffic_ledger WHERE ` + filter + ` ORDER BY sampled_at DESC LIMIT 1)`
	}
	change := func(alias string, node, insert bool) string {
		scope, email := 0, "''"
		if node {
			scope, email = 1, alias+".email"
		}
		mutation := "mutation+1"
		if insert {
			mutation = fmt.Sprintf("mutation+CASE WHEN %s.sampled_at < latest-%d THEN 1 ELSE 0 END", alias, trafficReorderWindow)
		}
		return fmt.Sprintf(`INSERT INTO traffic_usage_windows(subscription_id,scope,email,revision,mutation,latest)
		 VALUES(%s.subscription_id,%d,%s,1,1,%s)
		 ON CONFLICT(subscription_id,scope,email) DO UPDATE SET revision=revision+1,mutation=%s,latest=excluded.latest;`, alias, scope, email, latest(alias, node), mutation)
	}
	for _, event := range []string{"INSERT", "DELETE", "UPDATE"} {
		body := ""
		if event != "INSERT" {
			body += change("OLD", false, false) + change("OLD", true, false)
		}
		if event != "DELETE" {
			body += change("NEW", false, event == "INSERT") + change("NEW", true, event == "INSERT")
		}
		queries = append(queries, fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS traffic_window_%s AFTER %s ON traffic_ledger BEGIN %s END`, event, event, body))
	}
	// SQLite REPLACE does not run DELETE triggers when recursive_triggers is
	// off (the default). Mark the displaced row's scopes before the conflict is
	// resolved, including explicit rowid conflicts and UPDATE OR REPLACE.
	for _, event := range []string{"INSERT", "UPDATE"} {
		body := ""
		for _, node := range []bool{false, true} {
			scope, email := 0, "''"
			if node {
				scope, email = 1, "displaced.email"
			}
			conflict := "(displaced.id=NEW.id OR displaced.rowid=NEW.rowid)"
			if event == "UPDATE" {
				conflict += " AND displaced.rowid<>OLD.rowid"
			}
			body += fmt.Sprintf(`INSERT INTO traffic_usage_windows(subscription_id,scope,email,revision,mutation,latest)
			 SELECT displaced.subscription_id,%d,%s,1,1,%s FROM traffic_ledger AS displaced WHERE %s
			 ON CONFLICT(subscription_id,scope,email) DO UPDATE SET revision=revision+1,mutation=mutation+1;`, scope, email, latest("displaced", node), conflict)
		}
		queries = append(queries, fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS traffic_window_conflict_%s BEFORE %s ON traffic_ledger BEGIN %s END`, event, event, body))
	}
	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return nil
}
