package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func TestAgentStreamNegotiationStateAndResults(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "binary"}[modern], func(t *testing.T) {
			a, handler, admin := controllerFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			requireStatus(t, controllerRequest(t, handler, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "stream-node", "name": "stream", "address": "127.0.0.1", "connection": "websocket"}}), 200)
			creds, _ := a.DB.GetRecord(ctx, "_agentCredentials", "stream-node")
			server := httptest.NewServer(handler)
			defer server.Close()
			conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/agent/ws", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			ch, _ := agentwire.NewClient(a.MasterPublic)
			report := agentwire.Report{ServerID: "stream-node", Token: text(creds.Data, "serverToken"), Mode: "embedded", ConnectionMode: "websocket", Timestamp: time.Now().Unix(), Capabilities: map[string]bool{"connection_modes": true, "xray_stats": true}, Observation: map[string]any{"core": map[string]any{"running": true}}}
			if modern {
				report.Stream = agentwire.StreamOffer()
				report.Stream.TelemetryDelta = false // Prior binary protocol remains supported.
			}
			packet, _ := ch.Seal(report)
			if err := wsjson.Write(ctx, conn, agentwire.Hello{PublicKey: ch.PublicKey(), Packet: packet}); err != nil {
				t.Fatal(err)
			}
			if err := wsjson.Read(ctx, conn, &packet); err != nil {
				t.Fatal(err)
			}
			var reply agentwire.Reply
			if err := ch.Open(packet, &reply); err != nil {
				t.Fatal(err)
			}
			if !modern {
				if reply.Stream != nil || reply.Interval != 5 {
					t.Fatal("legacy behavior changed", reply)
				}
				packet, _ = ch.Seal(report)
				if err := wsjson.Write(ctx, conn, packet); err != nil {
					t.Fatal(err)
				}
				if err := wsjson.Read(ctx, conn, &packet); err != nil {
					t.Fatal(err)
				}
				if err := ch.Open(packet, &reply); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !reply.Stream.Valid() {
				t.Fatal("stream not selected", reply)
			}
			a.mu.Lock()
			initialSplit := a.peers["stream-node"].SplitHeartbeat
			a.mu.Unlock()
			if !initialSplit {
				t.Fatal("handshake did not establish the 15-second heartbeat grace")
			}
			exchange := func(update agentwire.Update) agentwire.Reply {
				t.Helper()
				update.Timestamp = time.Now().Unix()
				raw, err := ch.SealBinary(update, update.Kind == "telemetry")
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.Write(ctx, websocket.MessageBinary, raw); err != nil {
					t.Fatal(err)
				}
				kind, raw, err := conn.Read(ctx)
				if err != nil || kind != websocket.MessageBinary {
					t.Fatal("bad reply frame", err)
				}
				var out agentwire.Reply
				if err := ch.OpenBinary(raw, &out, false); err != nil || out.Error != "" {
					t.Fatal("bad stream reply", out, err)
				}
				return out
			}
			before, _ := a.DB.GetRecord(ctx, "_observations", "stream-node")
			task, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, "stream-node", "core.status", nil)
			if err != nil {
				t.Fatal(err)
			}
			reply = exchange(agentwire.Update{Kind: "heartbeat"})
			if len(reply.Commands) != 1 || reply.Commands[0].ID != task.ID {
				t.Fatal("command not delivered", reply)
			}
			after, _ := a.DB.GetRecord(ctx, "_observations", "stream-node")
			if after.Version != before.Version || after.Data["core"] == nil {
				t.Fatal("heartbeat erased or rewrote observation")
			}
			a.mu.Lock()
			peer := a.peers["stream-node"]
			caps, split := peer.Capabilities["xray_stats"], peer.SplitHeartbeat
			a.mu.Unlock()
			if !caps || !split {
				t.Fatal("heartbeat erased capabilities or split state")
			}
			second, err := a.queue(ctx, store.User{ID: "admin", Role: "admin"}, "stream-node", "core.status", nil)
			if err != nil {
				t.Fatal(err)
			}
			reply = exchange(agentwire.Update{Kind: "telemetry", Observation: map[string]any{"core": map[string]any{"running": false}}})
			if len(reply.Commands) != 0 {
				t.Fatal("more commands dispatched while batch in flight")
			}
			after, _ = a.DB.GetRecord(ctx, "_observations", "stream-node")
			if after.Data["core"].(map[string]any)["running"] != false {
				t.Fatal("telemetry not stored")
			}
			reply = exchange(agentwire.Update{Kind: "results", Results: []agentwire.Result{{ID: task.ID, Status: "success"}}})
			if len(reply.AckResults) != 1 || reply.AckResults[0] != task.ID {
				t.Fatal("missing result ACK", reply)
			}
			persisted, _ := a.DB.GetTask(ctx, task.ID)
			if persisted.Status != "success" {
				t.Fatal("ACK before result persistence")
			}
			reply = exchange(agentwire.Update{Kind: "heartbeat"})
			if len(reply.Commands) != 1 || reply.Commands[0].ID != second.ID {
				t.Fatal("next batch not delivered", reply)
			}
		})
	}
}

func TestSplitHeartbeatDirectFallbackGrace(t *testing.T) {
	a, _, _ := controllerFixture(t)
	server := store.Record{ID: "node", Data: map[string]any{"connection": "auto"}}
	a.peers["node"] = &peer{Transport: "WebSocket", LastSeen: time.Now().Add(-20 * time.Second), SplitHeartbeat: true}
	if a.shouldContactDirect(server) {
		t.Fatal("15-second heartbeat triggered premature fallback")
	}
	a.peers["node"].LastSeen = time.Now().Add(-46 * time.Second)
	if !a.shouldContactDirect(server) {
		t.Fatal("dead stream prevented fallback")
	}
}
