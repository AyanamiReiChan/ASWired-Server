package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"testing"
)

func TestUserSyncWaitsForDeployedInbound(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	actor := store.User{ID: "admin", Role: "admin"}
	task, err := a.queue(ctx, actor, "server", "core.users.sync", map[string]any{"inbound": "new-reality", "users": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	var observation store.Record
	for _, state := range []struct {
		core    map[string]any
		allowed bool
	}{
		{map[string]any{"config_exists": false}, false},
		{map[string]any{"config_exists": true, "inbound_tags": []string{"existing"}}, false},
		{map[string]any{"config_exists": true, "inbound_tags": []string{"existing", "new-reality"}}, true},
	} {
		observation, err = a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: "server", Data: map[string]any{"core": state.core}, Version: observation.Version})
		if err != nil {
			t.Fatal(err)
		}
		if a.permitDispatch(ctx, task) != state.allowed {
			t.Fatalf("incorrect dependency decision for %+v", state.core)
		}
		actual, err := a.DB.GetTask(ctx, task.ID)
		if err != nil || actual.Status != "queued" {
			t.Fatal("waiting task was incorrectly failed", err)
		}
	}
}
