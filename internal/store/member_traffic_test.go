package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func exerciseMemberTrafficDistribution(t *testing.T, db *Store) {
	t.Helper()
	ctx := context.Background()
	insert := func(id, sub, owner, server, email, direction string, raw int64, factor float64, at int64, gap int) {
		t.Helper()
		usageExec(t, db.db, db.Bind(`INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`), "distribution-"+id, server, sub, owner, email, direction, raw, factor, float64(raw)*factor, at, gap, "")
	}
	insert("start", "d-a", "distribution-owner", "jp", "a.jp", "uplink", 10, 2, 10, 0)
	insert("down", "d-a", "distribution-owner", "jp", "a.jp", "downlink", 30, 0.5, 11, 1)
	insert("us", "d-a", "distribution-owner", "us", "a.jp", "downlink", 5, 3, 12, 0)
	insert("retired", "d-retired", "distribution-owner", "jp", "old", "downlink", 7, 2, 13, 0)
	insert("second-before", "d-b", "distribution-owner", "jp", "b", "uplink", 1000, 1, 10, 0)
	insert("second-start", "d-b", "distribution-owner", "jp", "b", "uplink", 4, 0.25, 15, 0)
	insert("other-owner", "d-a", "different-owner", "jp", "a.jp", "downlink", 999, 1, 12, 0)
	insert("unassigned", "", "", "jp", "a.jp", "downlink", 999, 1, 12, 0)
	insert("before", "d-a", "distribution-owner", "jp", "a.jp", "downlink", 999, 1, 9, 0)
	insert("end", "d-a", "distribution-owner", "jp", "a.jp", "downlink", 999, 1, 20, 0)
	filters := []MemberTrafficWindow{{SubscriptionID: "d-a", Start: 10, End: 20}, {SubscriptionID: "d-b", Start: 15, End: 20}}
	groups, err := db.MemberTrafficDistribution(ctx, "distribution-owner", 10, 20, filters)
	if err != nil || len(groups) != 3 {
		t.Fatalf("current cycle groups: %+v %v", groups, err)
	}
	if groups[0].ServerID != "jp" || groups[0].Weighted != (TrafficUsage{Total: 35, Up: 20, Down: 15}) || groups[0].Raw != (TrafficUsage{Total: 40, Up: 10, Down: 30}) || !groups[0].Gap || groups[0].First != 10 || groups[0].Last != 11 {
		t.Fatalf("stored factor, directions, gap or boundary lost: %+v", groups[0])
	}
	if groups[1].ServerID != "us" || groups[1].Weighted.Total != 15 || groups[2].Weighted.Total != 1 {
		t.Fatalf("server identities or distinct cycle windows lost: %+v", groups)
	}
	groups, err = db.MemberTrafficDistribution(ctx, "distribution-owner", 10, 20, nil)
	if err != nil || len(groups) != 4 {
		t.Fatalf("fixed window lost retired history: %+v %v", groups, err)
	}
	var total float64
	for _, row := range groups {
		total += row.Weighted.Total
	}
	if total != 1065 {
		t.Fatalf("fixed window total: %v", total)
	}
	for _, owner := range []string{"", "missing"} {
		groups, err = db.MemberTrafficDistribution(ctx, owner, 10, 20, nil)
		if err != nil || len(groups) != 0 {
			t.Fatalf("empty owner %q: %+v %v", owner, groups, err)
		}
	}
	groups, err = db.MemberTrafficDistribution(ctx, "distribution-owner", 10, 20, []MemberTrafficWindow{})
	if err != nil || len(groups) != 0 {
		t.Fatal("empty current subscriptions included history", groups, err)
	}
	duplicate := append(filters, filters[0])
	if _, err = db.MemberTrafficDistribution(ctx, "distribution-owner", 10, 20, duplicate); err != ErrInvalid {
		t.Fatal("duplicate filters can double count", err)
	}
}

func TestMemberTrafficDistribution(t *testing.T) {
	db, _ := usageStore(t)
	exerciseMemberTrafficDistribution(t, db)
	for _, windows := range [][]MemberTrafficWindow{nil, {{SubscriptionID: "d-a", Start: 10, End: 20}}} {
		query, args := memberTrafficQuery("distribution-owner", 10, 20, windows)
		if plan := strings.Join(usageQueryPlan(t, db, query, args...), " "); !strings.Contains(plan, "traffic_ledger_owner_sampled") {
			t.Fatal("distribution stopped using owner/time index:", plan)
		}
	}
}

func TestMemberTrafficDistributionBatchesWindows(t *testing.T) {
	db, _ := usageStore(t)
	windows := []MemberTrafficWindow{}
	for i := range 260 {
		id := fmt.Sprintf("batch-%03d", i)
		usageExec(t, db.db, insertUsageRow, id, id, "downlink", 1, 15)
		windows = append(windows, MemberTrafficWindow{SubscriptionID: id, Start: 10, End: 20})
	}
	groups, err := db.MemberTrafficDistribution(context.Background(), "owner", 10, 20, windows)
	if err != nil || len(groups) != 260 {
		t.Fatalf("large account lost/duplicated subscriptions: %d %v", len(groups), err)
	}
}
