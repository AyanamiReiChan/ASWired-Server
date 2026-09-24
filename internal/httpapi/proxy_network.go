package httpapi

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

func (a *App) proxyIPv6Blocked(ctx context.Context) (bool, error) {
	var settings map[string]any
	if err := a.DB.GetSetting(ctx, "settings", &settings); err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	blocked, explicit := settings["blockProxyIPv6"].(bool)
	return !explicit || blocked, nil
}

func cloneProxyConfig(config map[string]any) (map[string]any, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(raw, &out)
	return out, err
}

func applyProxyNetworkDefaults(config map[string]any, blocked bool) (map[string]any, error) {
	cfg, err := cloneProxyConfig(config)
	if err != nil {
		return nil, err
	}
	metadata, _ := cfg["aswired"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["blockProxyIPv6"] = blocked
	cfg["aswired"] = metadata
	// A router ::/0 rule would also match the AAAA answers of dual-stack
	// domains under IPOnDemand/IPIfNonMatch, rejecting usable IPv4 websites.
	// Capability-gated Agent enforcement checks the actual client destination
	// after route selection instead, preserving user routing and DNS semantics.
	return cfg, nil
}

func proxyNetworkAction(action string) bool {
	return action == "core.config.apply" || action == "core.config.restore" || action == "core.config.test"
}

func (a *App) requireProxyIPv6Guard(serverID string) error {
	a.mu.Lock()
	p := a.peers[serverID]
	supported := p != nil && p.Capabilities["proxy_ipv6_guard"]
	a.mu.Unlock()
	if !supported {
		return errors.New("默认 IPv6 代理保护需要 Agent v1.0.10 或更新版本，请先升级 Agent，等待上报后重新下发配置")
	}
	return nil
}

func (a *App) proxyNetworkTaskParams(ctx context.Context, serverID, action string, params map[string]any) (map[string]any, error) {
	if !proxyNetworkAction(action) {
		return params, nil
	}
	blocked, err := a.proxyIPv6Blocked(ctx)
	if err != nil {
		return nil, err
	}
	if blocked {
		if err := a.requireProxyIPv6Guard(serverID); err != nil {
			return nil, err
		}
	}
	params = clone(params)
	if params == nil {
		params = map[string]any{}
	}
	params["blockProxyIPv6"] = blocked
	return params, nil
}

func (a *App) validateProxyNetworkTask(ctx context.Context, task store.Task, command agentwire.Command) error {
	if !proxyNetworkAction(command.Action) {
		return nil
	}
	blocked, err := a.proxyIPv6Blocked(ctx)
	if err != nil {
		return err
	}
	queued, explicit := command.Params["blockProxyIPv6"].(bool)
	if !explicit || queued != blocked {
		return errors.New("代理 IPv6 策略已变化或任务早于保护版本，请重新下发当前配置")
	}
	if blocked {
		return a.requireProxyIPv6Guard(task.ServerID)
	}
	return nil
}
