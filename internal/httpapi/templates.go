package httpapi

import (
	"context"
	"errors"
	"fmt"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/dop251/goja"
	"gopkg.in/yaml.v3"
	"regexp"
	"sort"
	"strings"
)

func mapList(v any) []map[string]any {
	out := []map[string]any{}
	if rows, ok := v.([]any); ok {
		for _, row := range rows {
			if m, ok := row.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}
func protocolSet(v string) map[string]bool {
	out := map[string]bool{}
	for _, s := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return r == '|' || r == ',' || r == ' ' }) {
		if s == "shadowsocks" {
			s = "ss"
		}
		out[s] = true
	}
	return out
}
func stableStrings(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range values {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
func expandTemplate(input map[string]any) (map[string]any, error) {
	cfg := clone(input)
	nodes := mapList(cfg["proxies"])
	groups := mapList(cfg["proxy-groups"])
	providers, _ := cfg["proxy-providers"].(map[string]any)
	providerNames := []string{}
	for name := range providers {
		providerNames = append(providerNames, name)
	}
	sort.Strings(providerNames)
	variables := map[string]string{}
	for k, v := range cfg {
		if s, ok := v.(string); ok {
			switch k {
			case "mode", "log-level", "external-controller", "external-ui", "external-ui-url", "secret", "interface-name", "tun", "geodata-loader", "global-client-fingerprint", "external-controller-unix", "profile", "find-process-mode":
			default:
				variables[k] = s
			}
		}
	}
	resolve := func(value string) (string, error) {
		seen := map[string]bool{}
		for {
			next, ok := variables[value]
			if !ok {
				return value, nil
			}
			if seen[value] {
				return "", errors.New("模板变量循环引用")
			}
			seen[value] = true
			if strings.TrimSpace(next) == "" {
				return "", errors.New("模板变量不能为空")
			}
			value = next
		}
	}
	if boolean(cfg, "region-groups") {
		regions := []struct{ name, pattern string }{{"香港", "(?i)香港|Hong Kong|\\bHK\\b"}, {"日本", "(?i)日本|Japan|Tokyo|\\bJP\\b"}, {"新加坡", "(?i)新加坡|Singapore|\\bSG\\b"}, {"美国", "(?i)美国|United States|\\bUS\\b"}, {"台湾", "(?i)台湾|台灣|Taiwan|\\bTW\\b"}}
		matched := map[string]bool{}
		for _, region := range regions {
			re := regexp.MustCompile(region.pattern)
			names := []string{}
			for _, n := range nodes {
				if re.MatchString(text(n, "name")) {
					names = append(names, text(n, "name"))
					matched[text(n, "name")] = true
				}
			}
			if len(names) > 0 {
				groups = append(groups, map[string]any{"name": region.name, "type": "select", "proxies": names})
			}
		}
		others := []string{}
		for _, n := range nodes {
			if !matched[text(n, "name")] {
				others = append(others, text(n, "name"))
			}
		}
		if len(others) > 0 {
			groups = append(groups, map[string]any{"name": "其他地区", "type": "select", "proxies": others})
		}
	}
	nodeMap := map[string]map[string]any{}
	for _, node := range nodes {
		name := text(node, "name")
		if name == "" || nodeMap[name] != nil {
			return nil, errors.New("节点名称为空或重复")
		}
		nodeMap[name] = node
	}
	groupMap := map[string]map[string]any{}
	for _, g := range groups {
		name := text(g, "name")
		if name == "" || groupMap[name] != nil || nodeMap[name] != nil {
			return nil, errors.New("代理组名称为空、重复或与节点冲突")
		}
		groupMap[name] = g
	}
	for _, g := range groups {
		name := text(g, "name")
		filter, e := resolve(text(g, "filter"))
		if e != nil {
			return nil, e
		}
		exclude, e := resolve(text(g, "exclude-filter"))
		if e != nil {
			return nil, e
		}
		var keep, drop *regexp.Regexp
		if filter != "" {
			keep, e = regexp.Compile(filter)
			if e != nil {
				return nil, fmt.Errorf("组%s筛选表达式无效", name)
			}
		}
		if exclude != "" {
			drop, e = regexp.Compile(exclude)
			if e != nil {
				return nil, fmt.Errorf("组%s排除表达式无效", name)
			}
		}
		included, excluded := protocolSet(text(g, "include-type")), protocolSet(text(g, "exclude-type"))
		matches := []string{}
		for _, node := range nodes {
			n, p := text(node, "name"), strings.ToLower(text(node, "type"))
			if keep != nil && !keep.MatchString(n) || drop != nil && drop.MatchString(n) || len(included) > 0 && !included[p] || excluded[p] {
				continue
			}
			matches = append(matches, n)
		}
		names := []string{}
		use := stringList(g["use"])
		for _, entry := range stringList(g["proxies"]) {
			switch strings.Trim(entry, "{} ") {
			case "PROXY_NODES", "PROXY NODES":
				names = append(names, matches...)
			case "PROXY_PROVIDERS", "PROXY PROVIDERS":
				use = append(use, providerNames...)
			default:
				names = append(names, entry)
			}
		}
		if boolean(g, "include-all") || boolean(g, "include-all-proxies") || filter != "" || len(included) > 0 {
			names = append(names, matches...)
		}
		if boolean(g, "include-all") || boolean(g, "include-all-providers") {
			use = append(use, providerNames...)
		}
		filtered := []string{}
		for _, entry := range stableStrings(names) {
			if node := nodeMap[entry]; node != nil {
				p := strings.ToLower(text(node, "type"))
				if keep != nil && !keep.MatchString(entry) || drop != nil && drop.MatchString(entry) || len(included) > 0 && !included[p] || excluded[p] {
					continue
				}
			}
			filtered = append(filtered, entry)
		}
		names = filtered
		if dialer := text(g, "dialer-proxy-group"); dialer != "" {
			if groupMap[dialer] == nil || dialer == name {
				return nil, errors.New("链式中转组不存在或引用自身")
			}
			for i, n := range names {
				if original := nodeMap[n]; original != nil {
					cloned := clone(original)
					cloneName := n + " · " + name
					if nodeMap[cloneName] != nil {
						return nil, errors.New("链式节点名称冲突")
					}
					cloned["name"] = cloneName
					cloned["dialer-proxy"] = dialer
					nodeMap[cloneName] = cloned
					nodes = append(nodes, cloned)
					names[i] = cloneName
				}
			}
		}
		g["proxies"] = stableStrings(names)
		if len(use) > 0 {
			for _, provider := range use {
				if _, ok := providers[provider]; !ok {
					return nil, errors.New("代理集合引用不存在")
				}
			}
			g["use"] = stableStrings(use)
		}
		for _, key := range []string{"include-all", "include-all-proxies", "include-all-providers", "include-type", "exclude-type", "filter", "exclude-filter", "dialer-proxy-group"} {
			delete(g, key)
		}
	}
	removed := map[string]bool{}
	for {
		changed := false
		for name, g := range groupMap {
			names := []string{}
			for _, entry := range stringList(g["proxies"]) {
				if !removed[entry] {
					names = append(names, entry)
				}
			}
			g["proxies"] = names
			if len(names) == 0 && len(stringList(g["use"])) == 0 {
				removed[name] = true
				delete(groupMap, name)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	visited, active := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(name string) error {
		if active[name] {
			return fmt.Errorf("代理组或链式引用循环: %s", name)
		}
		if visited[name] {
			return nil
		}
		active[name] = true
		g := groupMap[name]
		for _, entry := range stringList(g["proxies"]) {
			if groupMap[entry] != nil {
				if e := visit(entry); e != nil {
					return e
				}
			} else if n := nodeMap[entry]; n != nil {
				if dialer := text(n, "dialer-proxy"); dialer != "" {
					if groupMap[dialer] == nil {
						return errors.New("链式中转组被移除")
					}
					if e := visit(dialer); e != nil {
						return e
					}
				}
			} else if entry != "DIRECT" && entry != "REJECT" && entry != "REJECT-DROP" && entry != "PASS" && entry != "COMPATIBLE" {
				return fmt.Errorf("代理组引用不存在: %s", entry)
			}
		}
		active[name] = false
		visited[name] = true
		return nil
	}
	for name := range groupMap {
		if e := visit(name); e != nil {
			return nil, e
		}
	}
	finalGroups := []any{}
	for _, g := range groups {
		if !removed[text(g, "name")] {
			finalGroups = append(finalGroups, g)
		}
	}
	finalNodes := []any{}
	for _, n := range nodes {
		finalNodes = append(finalNodes, n)
	}
	cfg["proxy-groups"] = finalGroups
	cfg["proxies"] = finalNodes
	rules := []string{}
	for _, rule := range stringList(cfg["rules"]) {
		fields := strings.Split(rule, ",")
		policy := len(fields) - 1
		if policy > 0 && fields[policy] == "no-resolve" {
			policy--
		}
		if policy >= 0 && removed[fields[policy]] {
			continue
		}
		rules = append(rules, rule)
	}
	if len(rules) > 0 {
		cfg["rules"] = rules
	}
	for variable := range variables {
		delete(cfg, variable)
	}
	delete(cfg, "region-groups")
	return cfg, nil
}

func (a *App) applyRuleOverrides(ctx context.Context, sub store.Record, cfg map[string]any, format string) (map[string]any, error) {
	if boolean(sub.Data, "skipRuleOverrides") {
		return cfg, nil
	}
	rules, e := a.DB.ListRecords(ctx, "rules", "")
	if e != nil {
		return nil, e
	}
	for _, rule := range rules {
		r := rule.Data
		if disabledStatus(r) || r["enabled"] == false || text(r, "templateId") != "" && text(r, "templateId") != text(sub.Data, "templateId") {
			continue
		}
		if rule.OwnerID != "" && rule.OwnerID != sub.OwnerID {
			continue
		}
		kind := strings.ToLower(text(r, "type"))
		key := ""
		switch kind {
		case "dns":
			key = "dns"
		case "规则", "rules":
			key = "rules"
		case "规则集", "rule-providers":
			key = "rule-providers"
		default:
			continue
		}
		if format != "clash" && format != "mihomo" {
			return nil, errors.New("此覆写只支持Clash/Mihomo输出")
		}
		var overlay map[string]any
		if e := yaml.Unmarshal([]byte(text(r, "content")), &overlay); e != nil {
			return nil, e
		}
		value, ok := overlay[key]
		if !ok {
			return nil, fmt.Errorf("覆写缺少%s字段", key)
		}
		mode := text(r, "mode")
		if mode == "替换" || mode == "replace" {
			cfg[key] = value
		} else if key == "rules" {
			old, next := stringList(cfg[key]), stringList(value)
			if mode == "追加" || mode == "append" {
				cfg[key] = append(old, next...)
			} else {
				cfg[key] = append(next, old...)
			}
		} else {
			previous, _ := cfg[key].(map[string]any)
			if previous == nil {
				previous = map[string]any{}
			}
			next, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("覆写对象格式无效")
			}
			for k, v := range next {
				previous[k] = v
			}
			cfg[key] = previous
		}
	}
	return cfg, nil
}

func normalizeTemplate(raw string, version int) (map[string]any, []string, error) {
	if len(raw) > 1<<20 {
		return nil, nil, errors.New("模板超过1MiB")
	}
	warnings := []string{}
	if version == 2 || strings.Contains(raw, "custom_proxy_group=") {
		cfg := map[string]any{"mode": "rule", "proxy-groups": []any{}, "rules": []string{}}
		groups := []any{}
		rules := []string{}
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(key) {
			case "custom_proxy_group":
				parts := strings.Split(value, "`")
				if len(parts) < 3 {
					return nil, nil, errors.New("V2代理组结构无效")
				}
				g := map[string]any{"name": parts[0], "type": parts[1], "proxies": []string{}}
				refs, filters := []string{}, []string{}
				for _, p := range parts[2:] {
					if strings.HasPrefix(p, "[]") {
						refs = append(refs, p[2:])
					} else if strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "http://") {
						g["url"] = p
					} else if regexp.MustCompile(`^\d+(,\d+)*$`).MatchString(p) {
						g["interval"] = 300
						warnings = append(warnings, "V2复合测速参数规范为interval=300，请复核")
					} else {
						filters = append(filters, "(?:"+p+")")
					}
				}
				g["proxies"] = refs
				if len(filters) > 0 {
					g["include-all"] = true
					g["filter"] = strings.Join(filters, "|")
				}
				groups = append(groups, g)
			case "ruleset":
				parts := strings.SplitN(value, ",", 2)
				if len(parts) != 2 {
					return nil, nil, errors.New("V2规则引用结构无效")
				}
				if strings.HasPrefix(parts[1], "[]") {
					rule := strings.TrimPrefix(parts[1], "[]")
					if rule == "FINAL" {
						rule = "MATCH"
					}
					rules = append(rules, rule+","+parts[0])
				} else {
					warnings = append(warnings, "外部V2 ruleset须在规则集资源中显式配置: "+parts[1])
				}
			default:
				warnings = append(warnings, "未转换V2字段: "+key)
			}
		}
		cfg["proxy-groups"] = groups
		cfg["rules"] = rules
		return cfg, stableStrings(warnings), nil
	}
	var cfg map[string]any
	if e := yaml.Unmarshal([]byte(raw), &cfg); e != nil || cfg == nil {
		return nil, nil, errors.New("模板必须是有效YAML/JSON对象")
	}
	return cfg, warnings, nil
}
func (a *App) templateAction(ctx context.Context, u store.User, in actionInput) (bool, map[string]any, error) {
	switch in.Action {
	case "template.preview", "template.import", "template.history", "template.restore", "template.default", "template.visibility", "script.validate", "migration.preview":
	default:
		return false, nil, nil
	}
	if u.Role != "admin" {
		return true, nil, errors.New("需要管理员权限")
	}
	if in.Action == "script.validate" {
		script := defaultText(in.Params, "script", text(in.Params, "content"))
		if len(script) > 256<<10 {
			return true, nil, errors.New("脚本过大")
		}
		_, err := goja.Compile("aswired-override", script, false)
		return true, map[string]any{"success": err == nil, "message": "JavaScript语法校验完成；执行仍受主控限制"}, err
	}
	if in.Action == "migration.preview" {
		cfg, warnings, err := normalizeTemplate(text(in.Params, "content"), int(number(in.Params, "version")))
		return true, map[string]any{"format": "template", "normalized": cfg, "warnings": warnings, "applied": false}, err
	}
	result, err := a.templateManagementAction(ctx, u, in)
	return true, result, err
}
