package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// protectSubscriptionIPv6 runs after templates, rule overrides and JavaScript.
// It constrains client traffic without filtering or rewriting proxy endpoints.
// URI subscriptions cannot carry these global client settings; their managed
// server must enforce the destination policy instead.
func protectSubscriptionIPv6(content any, format string) (map[string]any, error) {
	raw, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil || config == nil {
		return nil, errors.New("订阅结果必须是配置对象")
	}
	object := func(parent map[string]any, key string) (map[string]any, error) {
		if parent[key] == nil {
			parent[key] = map[string]any{}
		}
		value, ok := parent[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("IPv6保护要求%s为配置对象", key)
		}
		return value, nil
	}
	prepend := func(parent map[string]any, key string, first any) error {
		var values []any
		if parent[key] != nil {
			var ok bool
			values, ok = parent[key].([]any)
			if !ok {
				return fmt.Errorf("IPv6保护要求%s为数组", key)
			}
		}
		// Comparison after JSON normalization keeps repeated application stable.
		encoded, _ := json.Marshal(first)
		var normalized any
		_ = json.Unmarshal(encoded, &normalized)
		next := []any{normalized}
		for _, value := range values {
			if !reflect.DeepEqual(value, normalized) {
				next = append(next, value)
			}
		}
		parent[key] = next
		return nil
	}

	switch format {
	case "clash", "stash":
		config["ipv6"] = false
		dns, err := object(config, "dns")
		if err != nil {
			return nil, err
		}
		dns["ipv6"] = false
		if err := prepend(config, "rules", "IP-CIDR6,::/0,REJECT,no-resolve"); err != nil {
			return nil, err
		}
	case "singbox":
		dns, err := object(config, "dns")
		if err != nil {
			return nil, err
		}
		dns["strategy"] = "ipv4_only"
		// A rule action overrides per-domain DNS rules as well as the global
		// default. Both reject actions use the sing-box 1.11+ schema, without
		// the removed legacy block outbound.
		// Always answer refused: the client's default reject throttling drops
		// queries after a burst, which would delay ordinary IPv4 fallback.
		if err := prepend(dns, "rules", map[string]any{"query_type": []string{"AAAA"}, "action": "reject", "no_drop": true}); err != nil {
			return nil, err
		}
		route, err := object(config, "route")
		if err != nil {
			return nil, err
		}
		if err := prepend(route, "rules", map[string]any{"ip_version": 6, "action": "reject"}); err != nil {
			return nil, err
		}
	case "egern":
		config["ipv6"] = false
		dns, err := object(config, "dns")
		if err != nil {
			return nil, err
		}
		if err := prepend(dns, "block_ips", "::/0"); err != nil {
			return nil, err
		}
		if err := prepend(config, "rules", map[string]any{"ip_cidr6": map[string]any{"match": "::/0", "policy": "REJECT", "no_resolve": true}}); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("此客户端格式不能写入结构化IPv6保护配置")
	}
	return config, nil
}
