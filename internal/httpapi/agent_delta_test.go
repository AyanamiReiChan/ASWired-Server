package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAgentDeltaReconstructsIdleCountersAndRejectsWrongBase(t *testing.T) {
	a, handler, admin := controllerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requireStatus(t, controllerRequest(t, handler, "POST", "/api/collections/servers", admin, map[string]any{"row": map[string]any{"id": "delta-node", "name": "delta", "address": "127.0.0.1", "connection": "websocket"}}), 200)
	creds, _ := a.DB.GetRecord(ctx, "_agentCredentials", "delta-node")
	server := httptest.NewServer(handler)
	defer server.Close()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/agent/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	ch, _ := agentwire.NewClient(a.MasterPublic)
	hello, _ := ch.Seal(agentwire.Report{ServerID: "delta-node", Token: text(creds.Data, "serverToken"), Mode: "embedded", ConnectionMode: "websocket", Timestamp: time.Now().Unix(), Stream: agentwire.StreamOffer()})
	if err := wsjson.Write(ctx, conn, agentwire.Hello{PublicKey: ch.PublicKey(), Packet: hello}); err != nil {
		t.Fatal(err)
	}
	var packet agentwire.Packet
	if err := wsjson.Read(ctx, conn, &packet); err != nil {
		t.Fatal(err)
	}
	var first agentwire.Reply
	if err := ch.Open(packet, &first); err != nil || !first.Stream.TelemetryDelta {
		t.Fatal("delta handshake failed", err)
	}
	exchange := func(update agentwire.Update) agentwire.Reply {
		t.Helper()
		update.Timestamp = time.Now().Unix()
		raw, err := ch.SealBinary(update, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, raw); err != nil {
			t.Fatal(err)
		}
		_, raw, err = conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var reply agentwire.Reply
		if err := ch.OpenBinary(raw, &reply, false); err != nil || reply.Error != "" {
			t.Fatal("stream failed", err, reply.Error)
		}
		return reply
	}
	keyA, keyB := "user>>>alice>>>traffic>>>uplink", "user>>>bob>>>traffic>>>downlink"
	at := time.Now().Add(-10 * time.Second).UnixMilli()
	base, _ := agentwire.CloneObservation(map[string]any{"core": map[string]any{"running": true, "config_sha256": strings.Repeat("a", 64)}, "xray_stats": map[string]any{"generation": 1, "timestamp": at, "reset": false, "counters": map[string]int64{keyA: 100, keyB: 200}}})
	full := agentwire.MakeObservationDelta(0, nil, base)
	if reply := exchange(agentwire.Update{Kind: "telemetry", TelemetrySeq: 1, Delta: &full}); reply.TelemetryAck != 1 {
		t.Fatal("missing full ACK")
	}
	next, _ := agentwire.CloneObservation(base)
	next["xray_stats"].(map[string]any)["timestamp"] = at + 5000
	delta := agentwire.MakeObservationDelta(1, base, next)
	if delta.Full {
		t.Fatal("idle sample sent in full")
	}
	if reply := exchange(agentwire.Update{Kind: "telemetry", TelemetrySeq: 2, Delta: &delta}); reply.TelemetryAck != 2 {
		t.Fatal("missing delta ACK")
	}
	for _, key := range []string{keyA, keyB} {
		var stamp int64
		err := a.DB.DB().QueryRowContext(ctx, a.DB.Bind(`SELECT sampled_at FROM traffic_cursors WHERE server_id=? AND counter_key=?`), "delta-node", key).Scan(&stamp)
		if err != nil || stamp != at+5000 {
			t.Fatal("unchanged counter was not a complete fresh sample", key, stamp, err)
		}
	}
	obs, _ := a.DB.GetRecord(ctx, "_observations", "delta-node")
	stats := obs.Data["xray_stats"].(map[string]any)
	if len(stats["counters"].(map[string]any)) != 2 || obs.Data["core"] == nil {
		t.Fatal("full view was not retained")
	}
	if reply := exchange(agentwire.Update{Kind: "heartbeat"}); reply.TelemetryAck != 0 || reply.Interval != 0 {
		t.Fatal("heartbeat reply was not compact", reply)
	}
	delta.Base = 99
	raw, _ := ch.SealBinary(agentwire.Update{Kind: "telemetry", Timestamp: time.Now().Unix(), TelemetrySeq: 3, Delta: &delta}, false)
	if err := conn.Write(ctx, websocket.MessageBinary, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("invalid baseline accepted")
	}
}
