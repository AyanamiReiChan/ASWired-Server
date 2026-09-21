package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

// The editor revision covers the effective routing and its available targets,
// not live telemetry updates to the server record.
func routingRevision(cfg map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"routing": cfg["routing"], "outbounds": cfg["outbounds"], "inbounds": cfg["inbounds"], "observatory": cfg["observatory"], "burstObservatory": cfg["burstObservatory"]})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func routeObjects(value any, field string) ([]any, error) {
	if value == nil {
		return []any{}, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s 必须是数组", field)
	}
	for _, item := range list {
		if _, ok := item.(map[string]any); !ok {
			return nil, fmt.Errorf("%s 的每一项必须是对象", field)
		}
	}
	return list, nil
}

func routeStrings(value any, field string) ([]string, error) {
	var list []string
	switch v := value.(type) {
	case []string:
		list = v
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s 必须是字符串数组", field)
			}
			list = append(list, s)
		}
	default:
		return nil, fmt.Errorf("%s 必须是字符串数组", field)
	}
	for _, s := range list {
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("%s 不能包含空值", field)
		}
	}
	return list, nil
}

func preserveAPIRules(previous, next map[string]any) {
	before, _ := routeObjects(previous["rules"], "rules")
	after, _ := routeObjects(next["rules"], "rules")
	rules := []any{}
	for _, item := range before {
		if text(item.(map[string]any), "outboundTag") == "api" {
			rules = append(rules, item)
		}
	}
	// Existing API rules cannot be changed or deleted by the routing editor.
	for _, item := range after {
		if text(item.(map[string]any), "outboundTag") != "api" {
			rules = append(rules, item)
		}
	}
	next["rules"] = rules
}

func prepareRouting(cfg map[string]any, defaultTag string) error {
	outs, err := routeObjects(cfg["outbounds"], "outbounds")
	if err != nil {
		return err
	}
	tags := map[string]bool{}
	for _, item := range outs {
		tag := text(item.(map[string]any), "tag")
		if tag == "" || tags[tag] {
			return fmt.Errorf("出站标签为空或重复：%s", tag)
		}
		tags[tag] = true
	}
	if defaultTag != "" {
		if !tags[defaultTag] {
			return fmt.Errorf("默认出站不存在或已禁用：%s", defaultTag)
		}
		for i, item := range outs {
			if text(item.(map[string]any), "tag") == defaultTag {
				ordered := []any{item}
				ordered = append(ordered, outs[:i]...)
				ordered = append(ordered, outs[i+1:]...)
				cfg["outbounds"] = ordered
				break
			}
		}
	}
	if cfg["routing"] == nil {
		return nil
	}
	routing, ok := cfg["routing"].(map[string]any)
	if !ok {
		return errors.New("routing 必须是对象")
	}
	if ds := text(routing, "domainStrategy"); ds != "" && ds != "AsIs" && ds != "IPIfNonMatch" && ds != "IPOnDemand" {
		return errors.New("不支持的 domainStrategy")
	}
	balances, err := routeObjects(routing["balancers"], "balancers")
	if err != nil {
		return err
	}
	balancerTags := map[string]bool{}
	observerKind := "observatory"
	for _, item := range balances {
		strategy, _ := item.(map[string]any)["strategy"].(map[string]any)
		if strings.EqualFold(text(strategy, "type"), "leastLoad") {
			observerKind = "burstObservatory"
		}
	}
	for _, item := range balances {
		b := item.(map[string]any)
		tag := text(b, "tag")
		if tag == "" || balancerTags[tag] {
			return fmt.Errorf("均衡器标签为空或重复：%s", tag)
		}
		balancerTags[tag] = true
		selectors, err := routeStrings(b["selector"], "selector")
		if err != nil {
			return err
		}
		if len(selectors) == 0 {
			return errors.New("均衡器需要至少一个出站前缀")
		}
		matched := false
		for _, prefix := range selectors {
			for out := range tags {
				if out != "block" && strings.HasPrefix(out, prefix) {
					matched = true
				}
			}
		}
		if !matched {
			return fmt.Errorf("均衡器 %s 没有可用出站", tag)
		}
		if fallback := text(b, "fallbackTag"); fallback != "" && !tags[fallback] {
			return fmt.Errorf("备用出站不存在：%s", fallback)
		}
		strategy, _ := b["strategy"].(map[string]any)
		switch strings.ToLower(text(strategy, "type")) {
		case "", "random", "roundrobin":
			if text(b, "fallbackTag") != "" {
				mergeRoutingObserver(cfg, observerKind, selectors)
			}
		case "leastping":
			mergeRoutingObserver(cfg, observerKind, selectors)
		case "leastload":
			mergeRoutingObserver(cfg, "burstObservatory", selectors)
		default:
			return errors.New("不支持的负载均衡策略")
		}
	}
	// Both strategies consume Xray's single Observatory feature. Burst reports
	// contain delay and load statistics, so mixed pools share the burst observer.
	if cfg["burstObservatory"] != nil && cfg["observatory"] != nil {
		old, _ := cfg["observatory"].(map[string]any)
		mergeRoutingObserver(cfg, "burstObservatory", stringList(old["subjectSelector"]))
		delete(cfg, "observatory")
	}
	rules, err := routeObjects(routing["rules"], "rules")
	if err != nil {
		return err
	}
	for i, item := range rules {
		rule := item.(map[string]any)
		if typ := text(rule, "type"); typ != "" && typ != "field" {
			return fmt.Errorf("规则 %d：type 仅支持 field", i+1)
		}
		out, bal := text(rule, "outboundTag"), text(rule, "balancerTag")
		if (out == "") == (bal == "") {
			return fmt.Errorf("规则 %d：必须且只能选择一个出站或均衡器", i+1)
		}
		if out != "" && !tags[out] && out != "api" {
			return fmt.Errorf("规则 %d：出站 %s 不存在或已禁用", i+1, out)
		}
		if bal != "" && !balancerTags[bal] {
			return fmt.Errorf("规则 %d：均衡器 %s 不存在", i+1, bal)
		}
		condition := false
		for key, value := range rule {
			switch key {
			case "type", "outboundTag", "balancerTag", "ruleTag":
				continue
			case "domain", "ip", "protocol", "source", "user", "inboundTag":
				values, err := routeStrings(value, key)
				if err != nil {
					return fmt.Errorf("规则 %d：%w", i+1, err)
				}
				if len(values) > 0 {
					condition = true
				}
			case "port", "sourcePort", "network", "attrs":
				s, ok := value.(string)
				if !ok {
					return fmt.Errorf("规则 %d：%s 必须是字符串", i+1, key)
				}
				if s != "" {
					condition = true
				}
				if key == "network" && s != "" && s != "tcp" && s != "udp" && s != "tcp,udp" {
					return errors.New("network 仅支持 tcp、udp 或 tcp,udp")
				}
			default:
				if value != nil {
					condition = true
				} // Preserve newer Xray fields for Agent validation.
			}
		}
		if !condition {
			return fmt.Errorf("规则 %d：需要匹配条件；全部流量可设置 network 为 tcp,udp", i+1)
		}
	}
	// Xray's control API rules must precede user traffic rules.
	ordered := []any{}
	for _, item := range rules {
		if text(item.(map[string]any), "outboundTag") == "api" {
			ordered = append(ordered, item)
		}
	}
	for _, item := range rules {
		if text(item.(map[string]any), "outboundTag") != "api" {
			ordered = append(ordered, item)
		}
	}
	routing["rules"] = ordered
	return nil
}

func mergeRoutingObserver(cfg map[string]any, key string, selectors []string) {
	original, _ := cfg[key].(map[string]any)
	observer := clone(original)
	if observer == nil {
		observer = map[string]any{}
	}
	subjects := stringList(observer["subjectSelector"])
	for _, s := range selectors {
		found := false
		for _, existing := range subjects {
			if existing == s {
				found = true
			}
		}
		if !found {
			subjects = append(subjects, s)
		}
	}
	observer["subjectSelector"] = subjects
	if key == "observatory" {
		if observer["probeURL"] == nil {
			observer["probeURL"] = "https://www.gstatic.com/generate_204"
		}
		if observer["probeInterval"] == nil {
			observer["probeInterval"] = "1m"
		}
		if observer["enableConcurrency"] == nil {
			observer["enableConcurrency"] = true
		}
	} else if observer["pingConfig"] == nil {
		observer["pingConfig"] = map[string]any{"destination": "https://www.gstatic.com/generate_204", "interval": "1m", "sampling": 2, "timeout": "10s"}
	}
	cfg[key] = observer
}

func (a *App) routingView(ctx context.Context, server store.Record, cfg map[string]any) map[string]any {
	routing, _ := cfg["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{"domainStrategy": "AsIs", "rules": []any{}, "balancers": []any{}}
	}
	outs, _ := routeObjects(cfg["outbounds"], "outbounds")
	ins, _ := routeObjects(cfg["inbounds"], "inbounds")
	names := map[string]string{"direct": "直连", "block": "拦截"}
	for _, collection := range []string{"inbounds", "outbounds"} {
		records, _ := a.DB.ListRecords(ctx, collection, "")
		for _, r := range records {
			if text(r.Data, "serverId") == server.ID {
				names[text(r.Data, "tag")] = text(r.Data, "name")
			}
		}
	}
	targets := []any{}
	inputs := []any{}
	for _, item := range outs {
		o := item.(map[string]any)
		tag := text(o, "tag")
		targets = append(targets, map[string]any{"tag": tag, "name": defaultText(namesAny(names), tag, tag), "protocol": o["protocol"]})
	}
	for _, item := range ins {
		o := item.(map[string]any)
		tag := text(o, "tag")
		inputs = append(inputs, map[string]any{"tag": tag, "name": defaultText(namesAny(names), tag, tag)})
	}
	defaultTag := ""
	if len(outs) > 0 {
		defaultTag = text(outs[0].(map[string]any), "tag")
	}
	return map[string]any{"routing": routing, "revision": routingRevision(cfg), "outbounds": targets, "inbounds": inputs, "defaultOutbound": defaultTag, "observatory": cfg["observatory"], "burstObservatory": cfg["burstObservatory"]}
}

func namesAny(names map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range names {
		out[k] = v
	}
	return out
}

func (a *App) routingAction(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	if u.Role != "admin" {
		return nil, errors.New("需要管理员权限")
	}
	server, err := a.DB.GetRecord(ctx, "servers", in.TargetID)
	if err != nil {
		return nil, err
	}
	cfg, err := a.compileServerDraft(ctx, server, false)
	if err != nil {
		return nil, err
	}
	if in.Action == "routing.get" {
		return a.routingView(ctx, server, cfg), nil
	}
	if text(in.Params, "revision") == "" || text(in.Params, "revision") != routingRevision(cfg) {
		return nil, errors.New("路由或出入站配置已变化，请重新载入后编辑")
	}
	proposed, ok := in.Params["routing"].(map[string]any)
	if !ok {
		return nil, errors.New("routing 必须是对象")
	}
	if _, err = routeObjects(proposed["rules"], "rules"); err != nil {
		return nil, err
	}
	previous, _ := cfg["routing"].(map[string]any)
	preserveAPIRules(previous, proposed)
	global, _ := server.Data["globalConfig"].(map[string]any)
	if global == nil {
		global = map[string]any{}
	}
	global["routing"] = proposed
	server.Data["globalConfig"] = global
	server.Data["routingDefaultOutbound"] = defaultText(in.Params, "defaultOutbound", "direct")
	preview, err := a.compileServer(ctx, server)
	if err != nil {
		return nil, err
	}
	view := a.routingView(ctx, server, preview)
	if in.Action == "routing.preview" {
		return view, nil
	}
	// SaveRecord performs an optimistic version check against concurrent edits.
	server, err = a.DB.SaveRecord(ctx, server)
	if err != nil {
		return nil, err
	}
	if boolean(in.Params, "apply") {
		task, err := a.queueCompile(ctx, u, server.ID)
		if err != nil {
			view["applyError"] = err.Error()
		} else {
			view["task"] = taskRow(task)
		}
	}
	view["saved"] = true
	return view, nil
}
