package httpapi

import (
	"encoding/json"
	"errors"
)

// Templates may arrange or rename proxies, but must not introduce connections
// outside the subscription's authorized nodes or change their credentials.
func validateSubscriptionOutput(content any, format string, nodes []clientNode) error {
	raw, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		return errors.New("订阅结果必须是配置对象")
	}
	if nonemptyNodeExtension(config["proxy-providers"]) {
		return errors.New("模板不能添加远程代理提供商，请通过订阅源导入")
	}
	field := "proxies"
	if format == "singbox" {
		field = "outbounds"
	}
	values, ok := config[field].([]any)
	if !ok {
		return errors.New("订阅结果缺少代理列表")
	}
	identity := func(proxy map[string]any) string {
		proxy = clone(proxy)
		delete(proxy, "name")
		delete(proxy, "tag")
		if format == "egern" {
			for key, value := range proxy {
				if p, ok := value.(map[string]any); ok {
					p = clone(p)
					delete(p, "name")
					proxy[key] = p
				}
			}
		}
		raw, _ := json.Marshal(proxy)
		return string(raw)
	}
	allowed := map[string]bool{}
	for _, node := range nodes {
		proxy := clashNode(node)
		if format == "singbox" {
			proxy = singboxNode(node)
		} else if format == "egern" {
			proxy = egernNode(node)
		}
		allowed[identity(proxy)] = true
	}
	for _, value := range values {
		proxy, ok := value.(map[string]any)
		if !ok {
			return errors.New("节点输出须为对象")
		}
		if format == "singbox" {
			switch text(proxy, "type") {
			case "direct", "block", "dns", "selector", "urltest":
				continue
			}
		}
		if !allowed[identity(proxy)] {
			return errors.New("模板或脚本修改了节点连接参数，或加入了套餐范围外节点")
		}
	}
	return nil
}
