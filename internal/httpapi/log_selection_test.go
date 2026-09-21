package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func TestLogDateRangeStrictBeijingInclusiveDays(t *testing.T) {
	from, to, err := logDateRange("2020-02-29", "2020-03-01")
	if err != nil || from.UTC().Format(time.RFC3339) != "2020-02-28T16:00:00Z" || to.UTC().Format(time.RFC3339) != "2020-03-01T16:00:00Z" {
		t.Fatalf("wrong timezone or inclusive end: %s %s %v", from, to, err)
	}
	for _, dates := range [][2]string{{"2026-9-17", "2026-09-17"}, {"2026-02-30", "2026-03-01"}, {"2026-09-18", "2026-09-17"}, {"2026-09-17 ", "2026-09-17"}, {"0000-01-01", "2026-09-17"}, {"", "2026-09-17"}, {"2026-09-17", "9999-12-31"}} {
		if _, _, err := logDateRange(dates[0], dates[1]); err == nil {
			t.Fatalf("invalid dates accepted: %v", dates)
		}
	}
}

func TestBulkLogRoutesRequireAdminAndWriteScope(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	if err := a.DB.CreateUser(ctx, store.User{ID: "bulk-member", Username: "bulk-member", Role: "user", PasswordHash: "unused", TokenVersion: 1}); err != nil {
		t.Fatal(err)
	}
	member, err := a.Signer.Issue("bulk-member", 1)
	if err != nil {
		t.Fatal(err)
	}
	issued := controllerRequest(t, h, http.MethodPost, "/api/actions", admin, map[string]any{"action": "token.create", "params": map[string]any{"name": "read-only", "scopes": []string{"read"}}})
	requireStatus(t, issued, http.StatusOK)
	readOnly := text(responseMap(t, issued), "token")
	input := map[string]any{"startDate": "2020-02-29", "endDate": "2020-02-29"}
	for _, collection := range []string{"tasks", "audit"} {
		for _, operation := range []string{"preview", "delete"} {
			path := "/api/logs/" + collection + "/" + operation
			requireStatus(t, controllerRequest(t, h, http.MethodPost, path, "", input), http.StatusUnauthorized)
			requireStatus(t, controllerRequest(t, h, http.MethodPost, path, member, input), http.StatusForbidden)
			requireStatus(t, controllerRequest(t, h, http.MethodPost, path, readOnly, input), http.StatusForbidden)
		}
	}
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/logs/tasks/delete", admin, input), http.StatusBadRequest)
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/logs/servers/preview", admin, input), http.StatusNotFound)
	requireStatus(t, controllerRequest(t, h, http.MethodPost, "/api/logs/tasks/preview", admin, map[string]any{"startDate": "invalid", "endDate": "2020-02-29"}), http.StatusBadRequest)
}

func TestBulkLogHTTPUsesCreatedDatesAndRequiresUnchangedPreview(t *testing.T) {
	a, h, admin := controllerFixture(t)
	ctx := context.Background()
	from, to, err := logDateRange("2020-02-29", "2020-02-29")
	if err != nil {
		t.Fatal(err)
	}
	for i, created := range []time.Time{from.Add(-time.Nanosecond), from, to.Add(-time.Nanosecond), to} {
		id := []string{"outside-before", "inside-first", "inside-last", "outside-after"}[i]
		status := "success"
		if i == 2 {
			status = "running"
		}
		if _, err = a.DB.SaveTask(ctx, store.Task{ID: id, Kind: "core.status", Status: status, CreatedAt: created, Input: json.RawMessage(`{"secret":true}`)}); err != nil {
			t.Fatal(err)
		}
		if err = a.DB.AppendAudit(ctx, store.AuditEvent{ID: id, Action: "boundary.test", CreatedAt: created}); err != nil {
			t.Fatal(err)
		}
	}
	for _, collection := range []string{"tasks", "audit"} {
		input := map[string]any{"startDate": "2020-02-29", "endDate": "2020-02-29"}
		previewResponse := controllerRequest(t, h, http.MethodPost, "/api/logs/"+collection+"/preview", admin, input)
		requireStatus(t, previewResponse, http.StatusOK)
		preview := responseMap(t, previewResponse)
		if preview["total"] != float64(2) || preview["timeZone"] != "Asia/Shanghai" {
			t.Fatalf("wrong boundary preview: %+v", preview)
		}
		input["fingerprint"] = preview["fingerprint"]
		otherDates := map[string]any{"startDate": "2020-03-01", "endDate": "2020-03-01", "fingerprint": preview["fingerprint"]}
		conflict := controllerRequest(t, h, http.MethodPost, "/api/logs/"+collection+"/delete", admin, otherDates)
		requireStatus(t, conflict, http.StatusConflict)
		if text(responseMap(t, conflict)["error"].(map[string]any), "code") != "preview_changed" {
			t.Fatal("unexpected mismatch error")
		}
		deletedResponse := controllerRequest(t, h, http.MethodPost, "/api/logs/"+collection+"/delete", admin, input)
		requireStatus(t, deletedResponse, http.StatusOK)
		deleted := responseMap(t, deletedResponse)
		wantDeleted, wantProtected := float64(2), float64(0)
		if collection == "tasks" {
			wantDeleted, wantProtected = 1, 1
		}
		if deleted["deleted"] != wantDeleted || deleted["protected"] != wantProtected {
			t.Fatalf("wrong batch result: %+v", deleted)
		}
	}
	for _, id := range []string{"outside-before", "inside-last", "outside-after"} {
		task, err := a.DB.GetTask(ctx, id)
		if err != nil || task.LogsDeleted {
			t.Fatalf("unexpected task deletion: %s %v", id, err)
		}
	}
	requireStatus(t, controllerRequest(t, h, http.MethodGet, "/api/collections/tasks/inside-first", admin, nil), http.StatusNotFound)
}

func TestBulkLogEmptyDeleteIsSuccessfulWithoutAuditGrowth(t *testing.T) {
	a, h, admin := controllerFixture(t)
	var before, after int
	if err := a.DB.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, collection := range []string{"tasks", "audit"} {
		input := map[string]any{"startDate": "2000-01-01", "endDate": "2000-01-01"}
		previewResponse := controllerRequest(t, h, http.MethodPost, "/api/logs/"+collection+"/preview", admin, input)
		requireStatus(t, previewResponse, http.StatusOK)
		preview := responseMap(t, previewResponse)
		if preview["total"] != float64(0) || preview["deletable"] != float64(0) || preview["protected"] != float64(0) {
			t.Fatal("empty preview returned records")
		}
		input["fingerprint"] = preview["fingerprint"]
		deletedResponse := controllerRequest(t, h, http.MethodPost, "/api/logs/"+collection+"/delete", admin, input)
		requireStatus(t, deletedResponse, http.StatusOK)
		result := responseMap(t, deletedResponse)
		if result["total"] != float64(0) || result["deleted"] != float64(0) || result["protected"] != float64(0) || result["timeZone"] != "Asia/Shanghai" {
			t.Fatalf("empty result mismatch: %+v", result)
		}
	}
	if err := a.DB.DB().QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&after); err != nil || after != before {
		t.Fatal("empty delete unexpectedly wrote audit logs")
	}
}
