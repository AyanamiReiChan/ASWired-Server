package httpapi

import (
	"context"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"strings"
	"testing"
	"time"
)

func TestAgentUpdateRejectsUnsafeOrConcurrentRelease(t *testing.T) {
	a, _ := subscriptionFixture(t)
	ctx := context.Background()
	actor := store.User{ID: "admin", Role: "admin"}
	valid := map[string]any{"version": "0.2.0-test.1", "sha256": strings.Repeat("a", 64), "url": "https://releases.example.test/agent"}
	for key, value := range map[string]string{"version": "latest", "sha256": "bad", "url": "http://releases.example.test/agent"} {
		params := clone(valid)
		params[key] = value
		if _, err := a.queueAgentUpdate(ctx, actor, "server", params); err == nil {
			t.Fatal("unsafe release allowed", key)
		}
	}
	if _, err := a.queueAgentUpdate(ctx, actor, "server", valid); err == nil {
		t.Fatal("offline Agent accepted")
	}
	a.peers["server"] = &peer{LastSeen: time.Now(), Capabilities: map[string]bool{"agent_update": true}}
	for i := 0; i < 110; i++ {
		if _, err := a.DB.SaveTask(ctx, store.Task{ID: fmt.Sprintf("sync-%03d", i), ServerID: "server", Kind: "core.users.sync", Status: "queued"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.queueAgentUpdate(ctx, actor, "server", valid); err != nil {
		t.Fatal(err)
	}
	if _, err := a.queueAgentUpdate(ctx, actor, "server", valid); err == nil {
		t.Fatal("concurrent upgrade accepted")
	}
}
