package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func logTaskFixture(t *testing.T, a *App, id, status, kind string, updated time.Time) store.Task {
	t.Helper()
	ctx := context.Background()
	task, err := a.DB.SaveTask(ctx, store.Task{ID: id, ServerID: "log-server", Kind: kind, Status: status, Input: json.RawMessage(`{"params":{"token":"private"}}`), Result: json.RawMessage(`{"private":"result"}`), Error: "private error", CreatedAt: updated.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.DB().ExecContext(ctx, a.DB.Bind(`UPDATE tasks SET updated_at=? WHERE id=?`), updated.UTC().Format("2006-01-02T15:04:05.000000000Z"), id); err != nil {
		t.Fatal(err)
	}
	task, err = a.DB.GetTask(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestLogDeletionRequiresAdminAndHidesTaskDetails(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	if err := a.DB.CreateUser(ctx, store.User{ID: "log-member", Username: "log-member", Role: "user", PasswordHash: "unused", TokenVersion: 1}); err != nil {
		t.Fatal(err)
	}
	member, err := a.Signer.Issue("log-member", 1)
	if err != nil {
		t.Fatal(err)
	}
	task := logTaskFixture(t, a, "finished-log", "success", "core.status", time.Now())
	if err = a.DB.AppendAudit(ctx, store.AuditEvent{ID: "delete-audit", Action: "test.log"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/collections/tasks/" + task.ID, "/api/collections/audit/delete-audit"} {
		requireStatus(t, controllerRequest(t, h, http.MethodDelete, path, "", nil), http.StatusUnauthorized)
		requireStatus(t, controllerRequest(t, h, http.MethodDelete, path, member, nil), http.StatusForbidden)
		requireStatus(t, controllerRequest(t, h, http.MethodDelete, path, admin, nil), http.StatusOK)
		requireStatus(t, controllerRequest(t, h, http.MethodDelete, path, admin, nil), http.StatusNotFound)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/tasks/"+task.ID, admin, nil), http.StatusNotFound)
	state := responseMap(t, controllerRequest(t, h, http.MethodGet, "/api/state", admin, nil))
	if state["capabilities"].(map[string]any)["logRetentionDays"] != float64(7) {
		t.Fatal("retention metadata missing")
	}
	for _, raw := range state["data"].(map[string]any)["tasks"].([]any) {
		if raw.(map[string]any)["id"] == task.ID {
			t.Fatal("deleted log visible")
		}
	}
	retry := controllerRequest(t, h, http.MethodPost, "/api/actions", admin, map[string]any{"action": "task.retry", "targetId": task.ID})
	if retry.Code < 400 || !strings.Contains(retry.Body.String(), "日志已清理") {
		t.Fatalf("deleted task retried: %d %s", retry.Code, retry.Body)
	}
	if a.finishTask(ctx, task.ServerID, agentwire.Result{ID: task.ID, Status: "success", Data: map[string]any{"late": true}}) {
		t.Fatal("late result resurrected deleted log")
	}
	for _, status := range []string{"queued", "running", "unknown"} {
		task := logTaskFixture(t, a, status, status, "core.status", time.Now().Add(-10*24*time.Hour))
		requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/collections/tasks/"+task.ID, admin, nil), http.StatusConflict)
	}
}

func TestLogRetentionUsesCompletionBoundaryAndPreservesOtherHistory(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	cutoff := now.Add(-7 * 24 * time.Hour)
	for _, status := range []string{"success", "failed", "unsupported", "superseded"} {
		logTaskFixture(t, a, "expired-"+status, status, "core.status", cutoff.Add(-time.Nanosecond))
	}
	for _, status := range []string{"queued", "running", "unknown"} {
		logTaskFixture(t, a, "active-"+status, status, "core.status", cutoff.Add(-24*time.Hour))
	}
	logTaskFixture(t, a, "boundary", "success", "core.status", cutoff)
	logTaskFixture(t, a, "recent-completion", "success", "core.status", now)
	if _, err := a.DB.DB().ExecContext(ctx, a.DB.Bind(`UPDATE tasks SET created_at=? WHERE id=?`), cutoff.Add(-24*time.Hour).Format("2006-01-02T15:04:05.000000000Z"), "recent-completion"); err != nil {
		t.Fatal(err)
	}
	for _, event := range []store.AuditEvent{{ID: "audit-old", Action: "old", CreatedAt: cutoff.Add(-time.Nanosecond)}, {ID: "audit-boundary", Action: "boundary", CreatedAt: cutoff}} {
		if err := a.DB.AppendAudit(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.DB.AddMetric(ctx, store.Metric{ID: "old-probe", ServerID: "log-server", RecordedAt: cutoff.Add(-24 * time.Hour), Values: map[string]any{"network_rx_bytes": 123}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "subscriptions", ID: "subscription-kept", OwnerID: "member", Data: map[string]any{"planId": "plan"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.DB().ExecContext(ctx, `INSERT INTO traffic_ledger(id,server_id,subscription_id,owner_id,email,direction,raw_bytes,factor,weighted_bytes,sampled_at,gap,gap_reason) VALUES('old-traffic','log-server','subscription-kept','member','email','uplink',123,1,123,1,0,'')`); err != nil {
		t.Fatal(err)
	}
	a.maintainLogRetention(ctx, now)
	for _, status := range []string{"success", "failed", "unsupported", "superseded"} {
		task, err := a.DB.GetTask(ctx, "expired-"+status)
		if err != nil || !task.LogsDeleted || len(task.Input) != 0 || len(task.Result) != 0 || task.Error != "" {
			t.Fatalf("expired %s retained logs: %+v %v", status, task, err)
		}
	}
	for _, id := range []string{"active-queued", "active-running", "active-unknown", "boundary", "recent-completion"} {
		task, err := a.DB.GetTask(ctx, id)
		if err != nil || task.LogsDeleted || len(task.Input) == 0 {
			t.Fatalf("protected log deleted: %s %v", id, err)
		}
	}
	var count int
	for query, want := range map[string]int{`SELECT COUNT(*) FROM audit_events WHERE id='audit-old'`: 0, `SELECT COUNT(*) FROM audit_events WHERE id='audit-boundary'`: 1, `SELECT COUNT(*) FROM metrics WHERE id='old-probe'`: 1, `SELECT COUNT(*) FROM traffic_ledger WHERE id='old-traffic'`: 1, `SELECT COUNT(*) FROM records WHERE collection='subscriptions' AND id='subscription-kept'`: 1} {
		if err := a.DB.DB().QueryRowContext(ctx, query).Scan(&count); err != nil || count != want {
			t.Fatalf("unrelated retention change: %s %d %v", query, count, err)
		}
	}
	a.maintainLogRetention(ctx, now)
}

func TestDeletedPolicyLogKeepsRetirementAndHistoryEvidence(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	task, _ := initialPolicyFixture(t, a, "unused-server")
	a.retireUnusedInitialPolicyTasks(ctx)
	task, err := a.DB.GetTask(ctx, task.ID)
	if err != nil || task.Status != "superseded" {
		t.Fatal("fixture not retired")
	}
	if err = a.clearTaskLog(ctx, task, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.reconcilePolicies(ctx, store.User{ID: "system", Role: "admin"})
	logs, err := a.DB.ListTasks(ctx, "unused-server", 10)
	if err != nil || len(logs) != 0 {
		t.Fatal("deleted retired policy was queued again")
	}
	if _, err = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "controlled-server", Data: map[string]any{"connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	history, err := a.queue(ctx, store.User{ID: "system", Role: "admin"}, "controlled-server", "core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "old"}}})
	if err != nil {
		t.Fatal(err)
	}
	history.Status = "success"
	history, err = a.DB.SaveTask(ctx, history)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.clearTaskLog(ctx, history, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a.noOtherPolicyTask(ctx, "controlled-server", "") {
		t.Fatal("past enforcement evidence lost")
	}
	a.reconcilePolicies(ctx, store.User{ID: "system", Role: "admin"})
	a.retireUnusedInitialPolicyTasks(ctx)
	logs, err = a.DB.ListTasks(ctx, "controlled-server", 10)
	if err != nil || len(logs) != 1 || logs[0].Status != "queued" {
		t.Fatalf("required policy clear was lost: %+v %v", logs, err)
	}
}

func TestLogRetentionRunsAtStartup(t *testing.T) {
	a, _, _ := controllerFixture(t)
	task := logTaskFixture(t, a, "startup-old", "success", "core.status", time.Now().Add(-8*24*time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, err := a.DB.GetTask(ctx, task.ID)
		if err == nil && current.LogsDeleted {
			return
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("startup retention did not run")
}

func TestDeletedFederationLogKeepsActivationAndRequestDeduplication(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	install := logTaskFixture(t, a, "install-log", "success", "federation.grant", time.Now())
	if err := a.clearTaskLog(ctx, install, time.Now()); err != nil {
		t.Fatal(err)
	}
	key, err := a.federationSigningKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := agentwire.SignFederationGrant(agentwire.FederationGrant{Protocol: agentwire.FederationProtocol, ID: "log-share", Revision: 1, ServerID: "log-server", AgentPublicKey: a.MasterPublic, ConsumerPublicKey: a.MasterPublic, Namespace: "tenant", Inbounds: map[string]string{"main": "inbound"}, Actions: []string{"status.get"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	shareToken := "test-share-token"
	if _, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_federationAgentShares", ID: "log-share", OwnerID: "admin", Data: map[string]any{"signed_grant": grant, "token_hash": hashOpaque(shareToken), "enabled": false, "install_task": install.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.activeFederationAgentShare(ctx, "log-share", shareToken); err != nil {
		t.Fatalf("deleted install task blocked activation: %v", err)
	}
	envelope := agentwire.FederationEnvelope{RequestID: "request-log", ShareID: "log-share", ConsumerPublicKey: a.MasterPublic}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+shareToken)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		return res
	}
	submitted := call(http.MethodPost, "/api/federation/agent/log-share/forward", envelope)
	requireStatus(t, submitted, http.StatusAccepted)
	jobID := text(responseMap(t, submitted), "job_id")
	task, err := a.DB.GetTask(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	task.Status = "success"
	task.Result = json.RawMessage(`{"packet":{"ciphertext":"private-result"}}`)
	task, err = a.DB.SaveTask(ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, controllerRequest(t, h, http.MethodDelete, "/api/collections/tasks/"+jobID, admin, nil), http.StatusOK)
	requireStatus(t, call(http.MethodGet, "/api/federation/agent/log-share/results/"+jobID, nil), http.StatusGone)
	duplicate := call(http.MethodPost, "/api/federation/agent/log-share/forward", envelope)
	requireStatus(t, duplicate, http.StatusAccepted)
	if text(responseMap(t, duplicate), "job_id") != jobID {
		t.Fatal("duplicate request changed job identity")
	}
	pending, err := a.DB.ListPendingTasks(ctx, "log-server", 10)
	if err != nil || len(pending) != 0 {
		t.Fatal("deleted completed request was dispatched again")
	}
}

func TestDeletedScheduleLogDoesNotResetNextRun(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	now := time.Now()
	task := logTaskFixture(t, a, "old-schedule", "success", "backup.create", now.Add(-8*24*time.Hour))
	next := now.Add(time.Hour).UTC().Format(time.RFC3339)
	schedule, err := a.DB.SaveRecord(ctx, store.Record{Collection: "schedules", ID: "scheduled-backup", Data: map[string]any{"enabled": true, "action": "backup.create", "intervalSeconds": 3600, "nextRun": next, "lastTaskId": task.ID}})
	if err != nil {
		t.Fatal(err)
	}
	a.maintainLogRetention(ctx, now)
	a.maintainSchedules(ctx)
	current, err := a.DB.GetRecord(ctx, "schedules", schedule.ID)
	if err != nil || current.Version != schedule.Version || text(current.Data, "nextRun") != next {
		t.Fatal("clearing logs changed schedule cadence")
	}
	logs, err := a.DB.ListTasks(ctx, "", 10)
	if err != nil || len(logs) != 0 {
		t.Fatal("schedule ran again after its old log was cleared")
	}
}
