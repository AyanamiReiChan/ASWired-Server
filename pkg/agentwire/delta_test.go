package agentwire

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func normalized(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	result, err := CloneObservation(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestObservationDeltaCompleteSamples(t *testing.T) {
	base := normalized(t, map[string]any{"core": map[string]any{"running": true, "description": strings.Repeat("static", 100)}, "xray_stats": map[string]any{"generation": 1, "timestamp": 1000, "counters": map[string]int64{"idle": 9007199254740993, "active": 4, "removed": 5}}, "obsolete": true})
	next := normalized(t, map[string]any{"core": map[string]any{"running": true, "description": strings.Repeat("static", 100), "null": nil}, "xray_stats": map[string]any{"generation": 1, "timestamp": 6000, "counters": map[string]int64{"idle": 9007199254740993, "active": 10, "added": 0}}})
	delta := MakeObservationDelta(1, base, next)
	if delta.Full {
		t.Fatal("small changes became a full snapshot")
	}
	raw, err := json.Marshal(delta)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "idle") || strings.Contains(string(raw), "description") {
		t.Fatal("unchanged state repeated", string(raw))
	}
	var decoded ObservationDelta
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	got, err := ApplyObservationDelta(1, base, decoded)
	if err != nil || !reflect.DeepEqual(got, next) {
		t.Fatalf("incomplete reconstruction: %v %+v", err, got)
	}
	if base["obsolete"] != true {
		t.Fatal("baseline was mutated")
	}
	stats := got["xray_stats"].(map[string]any)
	if stats["counters"].(map[string]any)["idle"] != json.Number("9007199254740993") {
		t.Fatal("counter precision lost")
	}
	if _, err := ApplyObservationDelta(2, base, decoded); err == nil {
		t.Fatal("wrong baseline accepted")
	}
	if _, err := ApplyObservationDelta(0, nil, ObservationDelta{}); err == nil {
		t.Fatal("missing baseline accepted")
	}
	stats["generation"] = json.Number("2")
	reset := MakeObservationDelta(2, next, got)
	if !reset.Full {
		t.Fatal("core restart did not reset the baseline")
	}
	full, err := ApplyObservationDelta(0, nil, MakeObservationDelta(0, nil, next))
	if err != nil || !reflect.DeepEqual(full, next) {
		t.Fatal("reconnect full snapshot failed", err)
	}
}

func TestObservationDeltaRejectsInvalidRemovalAndGrowth(t *testing.T) {
	for _, removed := range [][][]string{{{}}, {{"missing", "child"}}, {{"unknown"}}} {
		if _, err := ApplyObservationDelta(1, map[string]any{}, ObservationDelta{Base: 1, Removed: removed}); err == nil {
			t.Fatal("invalid removal accepted")
		}
	}
	base := map[string]any{"large": strings.Repeat("x", MaxPacket/2)}
	if _, err := ApplyObservationDelta(1, base, ObservationDelta{Base: 1, Set: map[string]any{"more": strings.Repeat("y", MaxPacket/2)}}); err == nil {
		t.Fatal("unbounded reconstructed state")
	}
}

func TestDeltaNegotiationAndCompactReplies(t *testing.T) {
	if !NegotiateStream(StreamOffer()).TelemetryDelta {
		t.Fatal("delta not selected")
	}
	old := StreamOffer()
	old.TelemetryDelta = false
	if NegotiateStream(old).TelemetryDelta {
		t.Fatal("old binary peer opted into delta")
	}
	r := Reply{Interval: 5, ConnectionMode: "websocket", ListenAddress: "localhost:1234", Commands: []Command{}}
	if len(CompactReply(r, "websocket", "localhost:1234")) != 0 {
		t.Fatal("empty reply retained static fields")
	}
	r.ConnectionMode = "auto"
	r.AckResults = []string{"result"}
	r.TelemetryAck = 7
	compact := CompactReply(r, "websocket", "localhost:1234")
	if compact["connection_mode"] != "auto" || compact["telemetry_ack"] != uint64(7) || compact["ack_results"] == nil {
		t.Fatal("lost control fields", compact)
	}
}
