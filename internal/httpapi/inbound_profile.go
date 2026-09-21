package httpapi

import (
	"errors"
	"fmt"
	"strings"
)

var errInboundProfile = errors.New("管理入站仅支持 VLESS TCP REALITY；旧入站请停用或明确转换后重新发布")

func validateRealityInboundProfile(row map[string]any) error {
	if !strings.EqualFold(strings.TrimSpace(text(row, "protocol")), "vless") || strings.Join(strings.Fields(strings.ToLower(text(row, "transport"))), "") != "tcp/reality" {
		return errInboundProfile
	}
	for key, want := range map[string]string{"network": "tcp", "security": "reality"} {
		if value := text(row, key); value != "" && !strings.EqualFold(strings.TrimSpace(value), want) {
			return errInboundProfile
		}
	}
	if value, exists := row["settings"]; exists && value != nil {
		settings, ok := value.(map[string]any)
		if !ok {
			return errors.New("入站 settings 必须为对象")
		}
		for key, value := range settings {
			if key != "decryption" || value != "none" {
				return fmt.Errorf("入站 settings.%s 不支持覆盖；用户凭据由主控管理", key)
			}
		}
	}
	if value, exists := row["streamSettings"]; exists && value != nil {
		stream, ok := value.(map[string]any)
		if !ok {
			return errors.New("入站 streamSettings 必须为对象")
		}
		for key, value := range stream {
			switch key {
			case "network":
				if value != "tcp" {
					return errInboundProfile
				}
			case "security":
				if value != "reality" {
					return errInboundProfile
				}
			case "sockopt":
				if _, ok := value.(map[string]any); !ok {
					return errors.New("入站 sockopt 必须为对象")
				}
			default:
				return fmt.Errorf("入站 streamSettings.%s 不支持覆盖；请使用 REALITY 专用字段", key)
			}
		}
	}
	return nil
}
