package httpapi

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

var trafficPoolMu sync.Mutex

func sharedTraffic(plan map[string]any) bool { return text(plan, "trafficMode") == "shared" }

type poolUsageKey struct{}
type poolUsageResult struct {
	usage store.TrafficPoolUsage
	err   error
}
type poolUsageSnapshot struct {
	mu    sync.Mutex
	pools map[string]poolUsageResult
}

// Each report, reconciliation and HTTP request observes one pool total, reused
// across all its subscriptions. The next operation always reads fresh revisions.
func freshPoolUsageSnapshot(ctx context.Context) context.Context {
	return context.WithValue(ctx, poolUsageKey{}, &poolUsageSnapshot{pools: map[string]poolUsageResult{}})
}

func withPoolUsageSnapshot(ctx context.Context) context.Context {
	if _, ok := ctx.Value(poolUsageKey{}).(*poolUsageSnapshot); ok {
		return ctx
	}
	return context.WithValue(ctx, poolUsageKey{}, &poolUsageSnapshot{pools: map[string]poolUsageResult{}})
}

func prepareTrafficPool(pool store.Record, plan store.Record, now time.Time) (store.Record, bool, bool) {
	initial := pool.ID == ""
	if initial {
		pool = store.Record{Collection: "_trafficPools", ID: plan.ID, Data: map[string]any{"cycleStart": cycleStamp(now), "cycleEnd": cycleStamp(nextCycleEnd(plan.Data, now)), "_cyclePolicyHash": cyclePolicyDigest(plan.Data)}}
	}
	reset := false
	end := dateTime(text(pool.Data, "cycleEnd"))
	// A genuine elapsed boundary takes precedence over a later policy edit.
	for !end.IsZero() && !now.Before(end) {
		pool.Data["cycleStart"] = cycleStamp(end)
		end = nextCycleEnd(plan.Data, end)
		pool.Data["cycleEnd"] = cycleStamp(end)
		reset = true
	}
	if text(pool.Data, "_cyclePolicyHash") != cyclePolicyDigest(plan.Data) {
		pool.Data["cycleEnd"] = cycleStamp(nextCycleEnd(plan.Data, now))
		pool.Data["_cyclePolicyHash"] = cyclePolicyDigest(plan.Data)
	}
	return pool, initial, reset
}

func (a *App) savePlanWithPool(ctx context.Context, plan store.Record) (store.Record, error) {
	trafficPoolMu.Lock()
	defer trafficPoolMu.Unlock()
	pool, err := a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.Record{}, err
	}
	if !sharedTraffic(plan.Data) && pool.ID == "" {
		return a.DB.SaveRecord(ctx, plan)
	}
	pool, initial, reset := prepareTrafficPool(pool, plan, time.Now().UTC())
	_, saved, err := a.DB.SaveTrafficPool(ctx, pool, initial, reset, &plan)
	return saved, err
}

func (a *App) ensureTrafficPool(ctx context.Context, plan store.Record) (store.Record, error) {
	trafficPoolMu.Lock()
	defer trafficPoolMu.Unlock()
	for attempts := 0; attempts < 3; attempts++ {
		// A caller may hold an older plan snapshot while an administrator edits
		// the cycle. Never revert the pool policy using that stale snapshot.
		currentPlan, readErr := a.DB.GetRecord(ctx, "plans", plan.ID)
		if readErr != nil {
			return store.Record{}, readErr
		}
		plan = currentPlan
		pool, err := a.DB.GetRecord(ctx, "_trafficPools", plan.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return store.Record{}, err
		}
		oldEnd, oldStart, oldDigest := text(pool.Data, "cycleEnd"), text(pool.Data, "cycleStart"), text(pool.Data, "_cyclePolicyHash")
		pool, initial, reset := prepareTrafficPool(pool, plan, time.Now().UTC())
		if !initial && !reset && oldEnd == text(pool.Data, "cycleEnd") && oldStart == text(pool.Data, "cycleStart") && oldDigest == text(pool.Data, "_cyclePolicyHash") {
			return pool, nil
		}
		saved, _, err := a.DB.SaveTrafficPool(ctx, pool, initial, reset, nil)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return saved, err
	}
	return store.Record{}, store.ErrConflict
}

func (a *App) sharedPoolUsage(ctx context.Context, plan store.Record) (store.TrafficPoolUsage, error) {
	snapshot, _ := ctx.Value(poolUsageKey{}).(*poolUsageSnapshot)
	if snapshot != nil {
		snapshot.mu.Lock()
		defer snapshot.mu.Unlock()
		if cached, ok := snapshot.pools[plan.ID]; ok {
			return cached.usage, cached.err
		}
	}
	_, err := a.ensureTrafficPool(ctx, plan)
	var usage store.TrafficPoolUsage
	if err == nil {
		usage, err = a.DB.TrafficPoolUsage(ctx, plan.ID, math.MaxInt64)
	}
	if snapshot != nil {
		snapshot.pools[plan.ID] = poolUsageResult{usage, err}
	}
	return usage, err
}

func (a *App) quotaUsage(ctx context.Context, sub, plan store.Record) (store.TrafficUsage, float64, error) {
	if sharedTraffic(plan.Data) {
		pool, err := a.sharedPoolUsage(ctx, plan)
		return pool.TrafficUsage, number(plan.Data, "limit"), err
	}
	total, up, down, err := a.subscriptionUsage(ctx, sub)
	return store.TrafficUsage{Total: total, Up: up, Down: down}, number(sub.Data, "limit"), err
}

func (a *App) subscriptionQuotaUsage(ctx context.Context, sub store.Record) (store.TrafficUsage, float64, error) {
	plan, err := a.DB.GetRecord(ctx, "plans", text(sub.Data, "planId"))
	if err != nil {
		return store.TrafficUsage{}, 0, err
	}
	return a.quotaUsage(ctx, sub, plan)
}

func effectiveQuotaLimit(sub, plan map[string]any) float64 {
	if sharedTraffic(plan) {
		return number(plan, "limit")
	}
	return number(sub, "limit")
}

// Only aggregates leave this function. The internal member window map must
// never appear in an admin/member/public subscription response.
func (a *App) projectTrafficPool(ctx context.Context, collection string, rec store.Record, row map[string]any) error {
	plan := rec
	if collection == "subscriptions" {
		var err error
		plan, err = a.DB.GetRecord(ctx, "plans", text(rec.Data, "planId"))
		if err != nil {
			return err
		}
	} else if collection != "plans" {
		return nil
	}
	row["trafficMode"] = "individual"
	if !sharedTraffic(plan.Data) {
		return nil
	}
	row["trafficMode"] = "shared"
	pool, err := a.sharedPoolUsage(ctx, plan)
	if err != nil {
		return err
	}
	limit := number(plan.Data, "limit")
	row["poolUsedBytes"], row["poolUploadBytes"], row["poolDownloadBytes"] = pool.Total, pool.Up, pool.Down
	row["poolLimit"], row["poolMemberCount"] = limit, pool.MemberCount
	row["poolCycleStart"], row["poolCycleEnd"] = pool.CycleStart, pool.CycleEnd
	row["poolRemainingBytes"] = nil
	if limit > 0 {
		row["poolRemainingBytes"] = math.Max(0, limit*gib-pool.Total)
	}
	return nil
}

func stripTrafficPoolProjection(row map[string]any) {
	for _, key := range []string{"poolUsedBytes", "poolUploadBytes", "poolDownloadBytes", "poolLimit", "poolRemainingBytes", "poolMemberCount", "poolCycleStart", "poolCycleEnd", "poolUsageError"} {
		delete(row, key)
	}
}
