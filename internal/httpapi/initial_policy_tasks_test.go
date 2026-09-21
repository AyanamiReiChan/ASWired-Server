package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func initialPolicyFixture(t *testing.T, a *App, serverID string) (store.Task, store.Record) {
	t.Helper()
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: serverID, Data: map[string]any{"name": serverID, "address": "127.0.0.1", "connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"policies": []any{}}
	task, err := a.queue(ctx, store.User{ID: "system", Role: "admin"}, serverID, "core.policy.apply", params)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(params)
	sum := sha256.Sum256(raw)
	state, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_policySync", ID: serverID, Data: map[string]any{"taskId": task.ID, "digest": hex.EncodeToString(sum[:]), "policies": []any{}}})
	if err != nil {
		t.Fatal(err)
	}
	return task, state
}

func TestInitialEmptyPoliciesDoNotCreateTasksForUnusedServers(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	for _, id := range []string{"unused", "previously-controlled"} {
		_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: id, Data: map[string]any{"name": id, "connection": "WebSocket"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	actor := store.User{ID: "system", Role: "admin"}
	history, err := a.queue(ctx, actor, "previously-controlled", "core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "previous-user", "emails": []string{"old@example.test"}}}})
	if err != nil {
		t.Fatal(err)
	}
	history.Status = "success"
	if _, err = a.DB.SaveTask(ctx, history); err != nil {
		t.Fatal(err)
	}
	a.reconcilePolicies(ctx, actor)
	a.reconcilePolicies(ctx, actor)
	empty, err := a.DB.ListTasks(ctx, "unused", 10)
	if err != nil || len(empty) != 0 {
		t.Fatal("unused server received an automatic empty policy task")
	}
	if _, err = a.DB.GetRecord(ctx, "_policySync", "unused"); err != store.ErrNotFound {
		t.Fatal("unused server acquired a policy state")
	}
	tasks, err := a.DB.ListTasks(ctx, "previously-controlled", 10)
	if err != nil || len(tasks) != 2 {
		t.Fatalf("previous enforcement was not followed by one clear task: %v %d", err, len(tasks))
	}
	a.retireUnusedInitialPolicyTasks(ctx)
	for _, task := range tasks {
		if task.ID == history.ID {
			continue
		}
		stored, _ := a.DB.GetTask(ctx, task.ID)
		if stored.Status != "queued" {
			t.Fatal("clear task for prior enforcement was retired")
		}
	}
}

func TestOnlyProvenInitialAutomaticEmptyPolicyTaskIsRetired(t *testing.T) {
	cases := []string{"initial-empty", "manual-empty-unlinked", "prior-policy", "prior-manual-empty", "second-sync-version", "current-inbound", "running", "success", "wrong-digest", "mismatched-target", "nonempty-input", "missing-policy-state"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			a, h, token := controllerFixture(t)
			ctx := context.Background()
			task, state := initialPolicyFixture(t, a, "target")
			actor := store.User{ID: "system", Role: "admin"}
			switch name {
			case "manual-empty-unlinked":
				manual, err := a.queue(ctx, actor, "target", "core.policy.apply", map[string]any{"policies": []any{}})
				if err != nil {
					t.Fatal(err)
				}
				task = manual
			case "prior-policy", "prior-manual-empty":
				policies := []any{}
				if name == "prior-policy" {
					policies = append(policies, map[string]any{"user_id": "old", "emails": []any{"old-email"}})
				}
				prior, err := a.queue(ctx, actor, "target", "core.policy.apply", map[string]any{"policies": policies})
				if err != nil {
					t.Fatal(err)
				}
				prior.Status = "success"
				if _, err = a.DB.SaveTask(ctx, prior); err != nil {
					t.Fatal(err)
				}
			case "second-sync-version":
				if _, err := a.DB.SaveRecord(ctx, state); err != nil {
					t.Fatal(err)
				}
			case "current-inbound":
				_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "inbound", Data: map[string]any{"name": "Existing", "serverId": "target"}})
				if err != nil {
					t.Fatal(err)
				}
			case "running", "success":
				task.Status = name
				var err error
				task, err = a.DB.SaveTask(ctx, task)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-digest":
				if err := a.DB.DeleteRecord(ctx, "_policySync", state.ID); err != nil {
					t.Fatal(err)
				}
				state.Version = 0
				state.Data["digest"] = "not-the-task-digest"
				if _, err := a.DB.SaveRecord(ctx, state); err != nil {
					t.Fatal(err)
				}
			case "mismatched-target":
				other, err := a.queue(ctx, actor, "target", "core.policy.apply", map[string]any{"policies": []any{}})
				if err != nil {
					t.Fatal(err)
				}
				_, err = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "another", Data: map[string]any{"name": "Another", "connection": "WebSocket"}})
				if err != nil {
					t.Fatal(err)
				}
				state.ID = "another"
				state.Version = 0
				state.Data["taskId"] = other.ID
				if _, err = a.DB.SaveRecord(ctx, state); err != nil {
					t.Fatal(err)
				}
			case "nonempty-input":
				other, err := a.queue(ctx, actor, "target", "core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "actual"}}})
				if err != nil {
					t.Fatal(err)
				}
				if err = a.DB.DeleteRecord(ctx, "_policySync", state.ID); err != nil {
					t.Fatal(err)
				}
				state.Version = 0
				state.Data["taskId"] = other.ID
				if _, err = a.DB.SaveRecord(ctx, state); err != nil {
					t.Fatal(err)
				}
				task = other
			case "missing-policy-state":
				if err := a.DB.DeleteRecord(ctx, "_policySync", state.ID); err != nil {
					t.Fatal(err)
				}
			}
			serverBefore, _ := a.DB.GetRecord(ctx, "servers", "target")
			a.retireUnusedInitialPolicyTasks(ctx)
			stored, err := a.DB.GetTask(ctx, task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if name == "initial-empty" {
				if stored.Status != "superseded" || stored.Error != unusedInitialPolicyMessage || text(taskRow(stored), "status") != "已撤回" {
					t.Fatalf("unused initial task not clearly retired: %+v", stored)
				}
				requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID}), http.StatusBadRequest)
				a.reconcilePolicies(ctx, actor)
				tasks, _ := a.DB.ListTasks(ctx, "target", 10)
				if len(tasks) != 1 {
					t.Fatal("retired automatic task was recreated")
				}
				manual, err := a.queue(ctx, actor, "target", "core.policy.apply", map[string]any{"policies": []any{map[string]any{"user_id": "later-manual-policy"}}})
				if err != nil {
					t.Fatal(err)
				}
				manual.Status = "success"
				if _, err = a.DB.SaveTask(ctx, manual); err != nil {
					t.Fatal(err)
				}
				a.reconcilePolicies(ctx, actor)
				latest, err := a.DB.GetRecord(ctx, "_policySync", "target")
				if err != nil || text(latest.Data, "taskId") == task.ID {
					t.Fatal("retired initial digest suppressed a necessary later clear")
				}
				clearTask, err := a.DB.GetTask(ctx, text(latest.Data, "taskId"))
				if err != nil || clearTask.Status != "queued" {
					t.Fatal("later manual enforcement did not receive clear policy")
				}
				a.retireUnusedInitialPolicyTasks(ctx)
				clearTask, _ = a.DB.GetTask(ctx, clearTask.ID)
				if clearTask.Status != "queued" {
					t.Fatal("later clear task was incorrectly retired")
				}
			} else if stored.Status != task.Status {
				t.Fatalf("ambiguous, manual, or needed clear task was changed: %s -> %s", task.Status, stored.Status)
			}
			serverAfter, _ := a.DB.GetRecord(ctx, "servers", "target")
			if serverAfter.Version != serverBefore.Version || serverAfter.ID != serverBefore.ID {
				t.Fatal("task cleanup changed server identity")
			}
		})
	}
}
