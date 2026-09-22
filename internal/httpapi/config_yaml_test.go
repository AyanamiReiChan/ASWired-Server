package httpapi

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigYAMLPreservesScalarTypes(t *testing.T) {
	input := map[string]any{
		"mixed-port": 7890,
		"proxies": []any{map[string]any{
			"port": 8443, "password": "001234", "tls": true,
			"reality-opts": map[string]any{"short-id": "0950000000000000"},
			"reserved":     []any{0, 127, 255},
		}},
		"large":    json.Number("9007199254740993"),
		"unsigned": json.Number("18446744073709551615"),
		"ratio":    json.Number("1.25"),
		"exponent": json.Number("1e3"),
		"disabled": false,
		"empty":    nil,
	}
	cloned := clone(input)
	raw, err := marshalConfigYAML(cloned)
	if err != nil {
		t.Fatal(err)
	}
	assertClashPorts(t, string(raw), 7890, 8443)
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	proxy := mapList(cfg["proxies"])[0]
	if proxy["password"] != "001234" || proxy["reality-opts"].(map[string]any)["short-id"] != "0950000000000000" || proxy["tls"] != true {
		t.Fatalf("proxy scalar types changed: %#v", proxy)
	}
	for i, value := range []int{0, 127, 255} {
		if proxy["reserved"].([]any)[i] != value {
			t.Fatalf("reserved values lost integer types: %v", proxy["reserved"])
		}
	}
	var exact struct {
		Large    int64  `yaml:"large"`
		Unsigned uint64 `yaml:"unsigned"`
	}
	if err := yaml.Unmarshal(raw, &exact); err != nil {
		t.Fatal(err)
	}
	if exact.Large != 9007199254740993 || exact.Unsigned != 18446744073709551615 || cfg["ratio"] != 1.25 || cfg["exponent"] != float64(1000) || cfg["disabled"] != false || cfg["empty"] != nil {
		t.Fatalf("configuration scalar types changed: %#v", cfg)
	}
	if _, ok := cloned["mixed-port"].(json.Number); !ok {
		t.Fatal("YAML marshaling modified the input")
	}
}

func TestConfigYAMLRejectsInvalidNumber(t *testing.T) {
	if _, err := marshalConfigYAML(map[string]any{"port": json.Number("invalid")}); err == nil {
		t.Fatal("invalid JSON number accepted")
	}
}
