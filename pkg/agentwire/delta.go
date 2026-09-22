package agentwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

// A delta always represents a complete sample. Missing fields mean unchanged;
// Removed explicitly deletes fields/counters. Values are cumulative, not diffs.
type ObservationDelta struct {
	Base    uint64         `json:"base"`
	Full    bool           `json:"full,omitempty"`
	Set     map[string]any `json:"set,omitempty"`
	Removed [][]string     `json:"removed,omitempty"`
}

func (d *ObservationDelta) UnmarshalJSON(raw []byte) error {
	type plain ObservationDelta
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode((*plain)(d))
}

// Freeze snapshots: runtime maps may contain typed counters, and accounting may
// mutate its input. UseNumber preserves integer counters through normalization.
func CloneObservation(value map[string]any) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := marshalPayload(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxPacket {
		return nil, errors.New("observation too large")
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	if !boundedObservation(result, 0) {
		return nil, errors.New("observation too deeply nested")
	}
	return result, nil
}

func boundedObservation(value any, depth int) bool {
	if depth > 64 {
		return false
	}
	switch v := value.(type) {
	case map[string]any:
		for _, child := range v {
			if !boundedObservation(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range v {
			if !boundedObservation(child, depth+1) {
				return false
			}
		}
	}
	return true
}

func observationDiff(old, next map[string]any, path []string, removed *[][]string) map[string]any {
	set := map[string]any{}
	for key, value := range next {
		prior, exists := old[key]
		if exists && reflect.DeepEqual(prior, value) {
			continue
		}
		before, oldMap := prior.(map[string]any)
		after, newMap := value.(map[string]any)
		if exists && oldMap && newMap {
			patch := observationDiff(before, after, append(append([]string{}, path...), key), removed)
			if len(patch) > 0 {
				set[key] = patch
			}
		} else {
			set[key] = value
		}
	}
	for key := range old {
		if _, exists := next[key]; !exists {
			*removed = append(*removed, append(append([]string{}, path...), key))
		}
	}
	return set
}

func observationGeneration(value map[string]any) any {
	stats, _ := value["xray_stats"].(map[string]any)
	return stats["generation"]
}

// Inputs are immutable normalized snapshots returned by CloneObservation.
func MakeObservationDelta(base uint64, old, next map[string]any) ObservationDelta {
	full := ObservationDelta{Base: base, Full: true, Set: next}
	if old == nil || !reflect.DeepEqual(observationGeneration(old), observationGeneration(next)) {
		return full
	}
	delta := ObservationDelta{Base: base}
	delta.Set = observationDiff(old, next, nil, &delta.Removed)
	patchBytes, _ := marshalPayload(delta)
	fullBytes, _ := marshalPayload(full)
	if len(patchBytes) >= len(fullBytes) {
		return full
	}
	return delta
}

func mergeObservation(target, set map[string]any) {
	for key, value := range set {
		before, oldMap := target[key].(map[string]any)
		after, newMap := value.(map[string]any)
		if oldMap && newMap {
			mergeObservation(before, after)
		} else {
			target[key] = value
		}
	}
}

func ApplyObservationDelta(base uint64, old map[string]any, delta ObservationDelta) (map[string]any, error) {
	if delta.Base != base || !boundedObservation(delta.Set, 0) {
		return nil, errors.New("invalid observation baseline")
	}
	if delta.Full {
		if delta.Set == nil || len(delta.Removed) != 0 {
			return nil, errors.New("invalid full observation")
		}
		return CloneObservation(delta.Set)
	}
	if old == nil {
		return nil, errors.New("missing observation baseline")
	}
	next, err := CloneObservation(old)
	if err != nil {
		return nil, err
	}
	for _, path := range delta.Removed {
		if len(path) == 0 || len(path) > 64 {
			return nil, errors.New("invalid removal path")
		}
		parent := next
		for _, key := range path[:len(path)-1] {
			var ok bool
			parent, ok = parent[key].(map[string]any)
			if !ok {
				return nil, errors.New("missing removal parent")
			}
		}
		key := path[len(path)-1]
		if _, exists := parent[key]; !exists {
			return nil, errors.New("missing removal field")
		}
		delete(parent, key)
	}
	mergeObservation(next, delta.Set)
	// Patches must not grow the retained baseline past the full-packet limit.
	return CloneObservation(next)
}

// Used only after telemetry_delta negotiation. Legacy replies retain their
// original shape. Keep changed connection parameters until the Agent reconnects.
func CompactReply(reply Reply, mode, listen string) map[string]any {
	out := map[string]any{}
	if reply.Error != "" {
		out["error"] = reply.Error
	}
	if len(reply.Commands) > 0 {
		out["commands"] = reply.Commands
	}
	if len(reply.AckResults) > 0 {
		out["ack_results"] = reply.AckResults
	}
	if reply.TelemetryAck > 0 {
		out["telemetry_ack"] = reply.TelemetryAck
	}
	if reply.ConnectionMode != "" && (reply.ConnectionMode != mode || reply.ListenAddress != listen) {
		out["connection_mode"], out["listen_address"] = reply.ConnectionMode, reply.ListenAddress
	}
	return out
}
