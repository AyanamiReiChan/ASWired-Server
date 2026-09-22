package httpapi

import (
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

// Configuration maps can contain json.Number after cloning or loading records.
// yaml.v3 otherwise encodes these as strings, which clients reject for ports.
func marshalConfigYAML(value any) ([]byte, error) {
	return yaml.Marshal(configYAMLValue{value})
}

type configYAMLValue struct {
	value any
}

func (v configYAMLValue) MarshalYAML() (any, error) {
	switch value := v.value.(type) {
	case json.Number:
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		tag := "!!int"
		if strings.ContainsAny(string(raw), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(raw)}, nil
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			out[key] = configYAMLValue{item}
		}
		return out, nil
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = configYAMLValue{item}
		}
		return out, nil
	default:
		return value, nil
	}
}
