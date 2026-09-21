package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func taskInbound(tag, protocol, network, security string) map[string]any {
	return map[string]any{"tag": tag, "protocol": protocol, "streamSettings": map[string]any{"network": network, "security": security}}
}

func TestManagedInboundTaskDispatchAndRetryRejectHistoricalProfiles(t *testing.T) {
	cases := []struct {
		name, action, link string
		params             map[string]any
	}{
		{"old managed tag", "core.config.apply", "", map[string]any{"config": map[string]any{"inbounds": []any{taskInbound("managed-tag", "vmess", "ws", "tls")}}}},
		{"old bridge tag", "core.config.apply", "", map[string]any{"config": map[string]any{"inbounds": []any{taskInbound("aswired-bridge-managed", "vless", "tcp", "none")}}}},
		{"old deferred listeners", "core.config.apply", "", map[string]any{"config": map[string]any{"inbounds": []any{}}, "auxiliary": map[string]any{"listeners": []any{map[string]any{"type": "anytls"}}}}},
		{"marked task nonmanaged tag", "core.config.apply", "", map[string]any{"managedInbounds": true, "config": map[string]any{"inbounds": []any{taskInbound("other-tag", "trojan", "tcp", "tls")}}}},
		{"marked task mixed listeners", "core.config.apply", "", map[string]any{"managedInbounds": true, "config": map[string]any{"inbounds": []any{taskInbound("managed-tag", "vless", "tcp", "reality"), taskInbound("internal", "socks", "tcp", "none")}}}},
		{"marked malformed config", "core.config.apply", "", map[string]any{"managedInbounds": true, "config": map[string]any{}}},
		{"linked auxiliary task", "mihomo.config.apply", "taskId", map[string]any{"listeners": []any{map[string]any{"name": "retired-listener", "type": "anytls"}}}},
		{"linked auxiliary bridge", "mihomo.config.apply", "bridgeTaskId", map[string]any{"listeners": []any{map[string]any{"name": "retired-listener", "type": "snell"}}}},
		{"managed auxiliary name", "mihomo.config.apply", "", map[string]any{"listeners": []any{map[string]any{"name": "managed-tag", "type": "anytls"}}}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			a, h, token := controllerFixture(t)
			ctx := context.Background()
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "connection": "WebSocket"}}); err != nil {
				t.Fatal(err)
			}
			data := realityInboundFixtureData()
			data["tag"] = "managed-tag"
			if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "managed", Data: data}); err != nil {
				t.Fatal(err)
			}
			actor, _ := a.DB.UserByUsername(ctx, "test-admin")
			task, err := a.queue(ctx, actor, "server", item.action, item.params)
			if err != nil {
				t.Fatal(err)
			}
			if item.link != "" {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "_auxiliarySync", ID: "server", Data: map[string]any{item.link: task.ID}}); err != nil {
					t.Fatal(err)
				}
			}
			if a.permitDispatch(ctx, task) {
				t.Fatal("historical unsupported configuration dispatched")
			}
			blocked, err := a.DB.GetTask(ctx, task.ID)
			if err != nil || blocked.Status != "failed" || !strings.Contains(blocked.Error, "重新发布") {
				t.Fatalf("blocked task lacks actionable failure: %v %+v", err, blocked)
			}
			before, err := a.DB.ListTasks(ctx, "server", 100)
			if err != nil {
				t.Fatal(err)
			}
			retry := controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID})
			requireStatus(t, retry, http.StatusBadRequest)
			if !strings.Contains(retry.Body.String(), "重新发布") {
				t.Fatal("retry does not explain migration")
			}
			after, err := a.DB.ListTasks(ctx, "server", 100)
			if err != nil || len(after) != len(before) {
				t.Fatal("rejected retry created another task")
			}
		})
	}
}

func TestRealityCompileTaskAndIndependentRawTasksRemainDispatchable(t *testing.T) {
	a, h, token := controllerFixture(t)
	ctx := context.Background()
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: "server", Data: map[string]any{"name": "Server", "connection": "WebSocket"}}); err != nil {
		t.Fatal(err)
	}
	data := realityInboundFixtureData()
	data["tag"] = "managed-tag"
	if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "managed", Data: data}); err != nil {
		t.Fatal(err)
	}
	actor, _ := a.DB.UserByUsername(ctx, "test-admin")
	managed, err := a.queueCompile(ctx, actor, "server")
	if err != nil {
		t.Fatal(err)
	}
	var command struct {
		Params map[string]any `json:"params"`
	}
	if json.Unmarshal(managed.Input, &command) != nil || !boolean(command.Params, "managedInbounds") {
		t.Fatal("compiler did not mark managed task")
	}
	if !a.permitDispatch(ctx, managed) {
		t.Fatal("Reality compilation blocked")
	}
	tasks := []struct {
		action string
		params map[string]any
	}{
		{"core.config.apply", map[string]any{"config": map[string]any{"inbounds": []any{taskInbound("manual-internal-api", "dokodemo-door", "tcp", "none")}}}},
		{"core.config.apply", map[string]any{"config": map[string]any{"inbounds": []any{taskInbound("managed-tag", "vless", "tcp", "reality"), taskInbound("manual-internal-socks", "socks", "tcp", "none")}}}},
		{"mihomo.config.apply", map[string]any{"listeners": []any{map[string]any{"name": "independent-external", "type": "anytls"}}}},
		{"mihomo.config.apply", map[string]any{"listeners": []any{}}},
	}
	saved := []store.Task{managed}
	for _, item := range tasks {
		task, err := a.queue(ctx, actor, "server", item.action, item.params)
		if err != nil {
			t.Fatal(err)
		}
		if !a.permitDispatch(ctx, task) {
			t.Fatal("independent raw or cleanup task blocked")
		}
		saved = append(saved, task)
	}
	for _, task := range saved {
		task.Status = "failed"
		if _, err = a.DB.SaveTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID}), http.StatusAccepted)
	}
}

func TestManagedTaskOwnershipSurvivesInboundDeletionAndRenaming(t *testing.T) {
	for _, mutation := range []string{"delete", "rename-tag", "move-server"} {
		t.Run(mutation, func(t *testing.T) {
			a, h, token := controllerFixture(t)
			ctx := context.Background()
			for _, id := range []string{"server", "other-server"} {
				if _, err := a.DB.SaveRecord(ctx, store.Record{Collection: "servers", ID: id, Data: map[string]any{"name": id, "connection": "WebSocket"}}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := a.DB.SaveRecord(ctx, store.Record{Collection: "inbounds", ID: "legacy", Data: map[string]any{"name": "Legacy", "serverId": "server", "protocol": "VMess", "transport": "TCP", "tag": "old-managed-tag", "port": 443, "status": "禁用"}})
			if err != nil {
				t.Fatal(err)
			}
			actor, _ := a.DB.UserByUsername(ctx, "test-admin")
			tasks := []store.Task{}
			for _, tag := range []string{"old-managed-tag", "aswired-bridge-legacy"} {
				task, err := a.queue(ctx, actor, "server", "core.config.apply", map[string]any{"config": map[string]any{"inbounds": []any{taskInbound(tag, "vless", "tcp", "none")}}})
				if err != nil {
					t.Fatal(err)
				}
				tasks = append(tasks, task)
			}
			listener, err := a.queue(ctx, actor, "server", "mihomo.config.apply", map[string]any{"listeners": []any{map[string]any{"name": "old-managed-tag", "type": "anytls"}}})
			if err != nil {
				t.Fatal(err)
			}
			tasks = append(tasks, listener)
			if mutation == "delete" {
				requireStatus(t, controllerRequest(t, h, "DELETE", "/api/collections/inbounds/legacy", token, nil), http.StatusOK)
			} else {
				patch := map[string]any{"name": "Legacy", "status": "禁用"}
				if mutation == "rename-tag" {
					patch["tag"] = "new-managed-tag"
				} else {
					patch["serverId"] = "other-server"
				}
				requireStatus(t, controllerRequest(t, h, "PUT", "/api/collections/inbounds/legacy", token, map[string]any{"row": patch}), http.StatusOK)
			}
			history, err := a.DB.ListRecords(ctx, "_managedInboundTags", "")
			if err != nil || len(history) != 1 || text(history[0].Data, "serverId") != "server" {
				t.Fatal("original private tag ownership was not retained")
			}
			for _, task := range tasks {
				if a.permitDispatch(ctx, task) {
					t.Fatal("old unmanaged-looking task dispatched after record mutation")
				}
				requireStatus(t, controllerRequest(t, h, "POST", "/api/actions", token, map[string]any{"action": "task.retry", "targetId": task.ID}), http.StatusBadRequest)
			}
			requireStatus(t, controllerRequest(t, h, "GET", "/api/collections/_managedInboundTags", token, nil), http.StatusNotFound)
		})
	}
}
