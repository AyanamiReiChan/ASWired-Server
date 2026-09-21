package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
	"time"
)

func TestTelegramAdminConfirmationAndMemberPreferences(t *testing.T) {
	a, _, _ := controllerFixture(t)
	ctx := context.Background()
	user, _ := a.DB.UserByUsername(ctx, "test-admin")
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_telegramBindings", ID: "42", OwnerID: user.ID, Data: map[string]any{"chatId": "42"}})
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "node", "address": "127.0.0.1"}})
	message, e := a.telegramCommand(ctx, "42", "/restart server")
	if e != nil {
		t.Fatal(e)
	}
	tasks, _ := a.DB.ListTasks(ctx, "", 100)
	if len(tasks) != 0 {
		t.Fatal("unconfirmed restart dispatched")
	}
	parts := strings.Split(message, "/confirm ")
	code := strings.Fields(parts[1])[0]
	if _, e = a.telegramCommand(ctx, "42", "/confirm "+code); e != nil {
		t.Fatal(e)
	}
	if _, e = a.telegramCommand(ctx, "42", "/confirm "+code); e == nil {
		t.Fatal("confirmation replay accepted")
	}
	tasks, _ = a.DB.ListTasks(ctx, "", 100)
	if len(tasks) != 1 || tasks[0].Kind != "core.restart" {
		t.Fatal("confirmation did not queue actual restart")
	}
	if _, e = a.telegramCommand(ctx, "42", "/notify off"); e != nil {
		t.Fatal(e)
	}
	pref, _ := a.DB.GetRecord(ctx, "_telegramPreferences", user.ID)
	if pref.Data["enabled"] != false {
		t.Fatal("notification preference ignored")
	}
	user.Role = "user"
	if e = a.DB.UpdateUser(ctx, user); e != nil {
		t.Fatal(e)
	}
	if _, e = a.telegramCommand(ctx, "42", "/codescreate plan 30 1"); e == nil {
		t.Fatal("member created admin redemption code")
	}
	message, e = a.telegramCommand(ctx, "42", "/unbind")
	if e != nil {
		t.Fatal(e)
	}
	parts = strings.Split(message, "/unbindconfirm ")
	code = strings.Fields(parts[1])[0]
	if _, e = a.telegramCommand(ctx, "42", "/unbindconfirm "+code); e != nil {
		t.Fatal(e)
	}
	if _, e = a.DB.GetRecord(ctx, "_telegramBindings", "42"); e == nil {
		t.Fatal("binding not removed")
	}
}
func TestSubscriptionExpiryReminderStagesAreDeduplicated(t *testing.T) {
	a, sub := subscriptionFixture(t)
	ctx := context.Background()
	expiry := time.Now().UTC().Add(7 * 24 * time.Hour)
	sub.Data["expires"] = expiry.Format(time.RFC3339)
	if _, e := a.DB.SaveRecord(ctx, sub); e != nil {
		t.Fatal(e)
	}
	for _, days := range []int{7, 7, 3, 3, 1, 1} {
		a.subscriptionExpiryEvents(ctx, expiry.Add(-time.Duration(days)*24*time.Hour).Add(time.Minute))
	}
	rows, _ := a.DB.ListRecords(ctx, "_notificationEvents", sub.OwnerID)
	if len(rows) != 3 {
		t.Fatalf("wanted 7/3/1 once, got %d", len(rows))
	}
	a.subscriptionExpiryEvents(ctx, expiry.Add(time.Hour))
	rows, _ = a.DB.ListRecords(ctx, "_notificationEvents", sub.OwnerID)
	if len(rows) != 3 {
		t.Fatal("expired subscription generated pre-expiry notification")
	}
}
