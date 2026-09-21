package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLifecycleManagedNodeMetadataSurvivesRefresh(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "audit-in", Data: realityInboundFixtureData()})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	row, err := a.DB.GetRecord(ctx, "nodes", "inbound-audit-in")
	if err != nil {
		t.Fatal(err)
	}
	row.Data["name"] = "Local display name"
	row.Data["tags"] = []string{"local-tag"}
	if _, err = a.DB.SaveRecord(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err = a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	row, err = a.DB.GetRecord(ctx, "nodes", "inbound-audit-in")
	if err != nil {
		t.Fatal(err)
	}
	if text(row.Data, "name") != "Local display name" || len(stringList(row.Data["tags"])) != 1 {
		t.Fatalf("display metadata overwritten: name=%q tags=%v", text(row.Data, "name"), row.Data["tags"])
	}
}

func TestLifecycleManagedNodeDeletionSurvivesRefresh(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "audit-delete", Data: realityInboundFixtureData()})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("DELETE", "/api/nodes/inbound-audit-delete", nil)
	req = req.WithContext(context.WithValue(ctx, userKey{}, store.User{ID: "admin", Role: "admin"}))
	req.SetPathValue("collection", "nodes")
	req.SetPathValue("id", "inbound-audit-delete")
	result := httptest.NewRecorder()
	a.delete(result, req)
	if result.Code != 200 {
		t.Fatalf("delete failed: %d %s", result.Code, result.Body.String())
	}
	if err = a.refreshInboundNodes(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.GetRecord(ctx, "nodes", "inbound-audit-delete"); err == nil {
		t.Fatal("deleted managed node regenerated because inbound remains")
	}
	if _, err = a.DB.GetRecord(ctx, "inbounds", "audit-delete"); err == nil {
		t.Fatal("authoritative inbound remains")
	}
	var response struct {
		Task map[string]any `json:"task"`
	}
	if err = json.Unmarshal(result.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	task, err := a.DB.GetTask(ctx, text(response.Task, "id"))
	if err != nil {
		t.Fatal("deletion command missing", err)
	}
	var command agentwire.Command
	if err = json.Unmarshal(task.Input, &command); err != nil {
		t.Fatal(err)
	}
	config, _ := command.Params["config"].(map[string]any)
	if len(config["inbounds"].([]any)) != 0 {
		t.Fatal("removal command still contains deleted inbound")
	}
	config["inbounds"] = []any{map[string]any{"tag": "reality-in"}}
	if a.rejectDeletedInboundReplay(ctx, "server", config) == nil {
		t.Fatal("stale configuration can restore deleted inbound")
	}
}

func TestLifecycleNoResetPreservesBillingPeriod(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	plan, err := a.DB.GetRecord(ctx, "plans", "plan")
	if err != nil {
		t.Fatal(err)
	}
	plan.Data["reset"] = "不重置"
	plan.Data["cycleDays"] = 30
	if _, err = a.DB.SaveRecord(ctx, plan); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().AddDate(0, 0, -31)
	sub.Data["cycleStart"] = start.Format(time.RFC3339Nano)
	// Simulate a stored cycle written by the old implementation.
	sub.Data["cycleEnd"] = start.AddDate(0, 0, 30).Format(time.RFC3339Nano)
	if _, err = a.DB.SaveRecord(ctx, sub); err != nil {
		t.Fatal(err)
	}
	a.expireSubscriptions(ctx)
	after, err := a.DB.GetRecord(ctx, "subscriptions", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if text(after.Data, "cycleStart") != text(sub.Data, "cycleStart") {
		t.Fatal("no-reset plan advanced cycleStart and excluded earlier usage")
	}
	if text(after.Data, "cycleEnd") != "" {
		t.Fatal("legacy finite cycle end was not cleared")
	}
}
