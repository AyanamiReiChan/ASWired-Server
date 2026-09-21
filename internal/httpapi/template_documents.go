package httpapi

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
)

var templateMu sync.Mutex

func templateType(value string) string {
	switch strings.ToLower(value) {
	case "", "clash", "mihomo":
		return "Clash"
	case "surge":
		return "Surge"
	case "loon":
		return "Loon"
	default:
		return ""
	}
}

func templateMatches(row map[string]any, format string) bool {
	kind := templateType(text(row, "type"))
	return kind == "Clash" && (format == "clash" || format == "stash") || strings.EqualFold(kind, format)
}

func blankTemplate(kind string) string {
	if kind == "Clash" {
		return "mode: rule\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies: [DIRECT]\n    include-all: true\nrules:\n  - MATCH,PROXY\n"
	}
	return "[General]\n\n[Proxy]\n\n[Proxy Group]\nPROXY = select, {{PROXY_NODES}}, DIRECT\n\n[Rule]\nFINAL,PROXY\n"
}

// Parse sections with ini, then keep their bodies raw so client-specific rule syntax and comments survive.
func parseINITemplate(raw string) (*ini.File, error) {
	if len(raw) > 1<<20 || strings.ContainsRune(raw, '\x00') {
		return nil, errors.New("模板超过1MiB或包含非法字符")
	}
	opts := ini.LoadOptions{AllowBooleanKeys: true, AllowShadows: true, IgnoreInlineComment: true, KeyValueDelimiters: "=", AllowNonUniqueSections: true}
	index, err := ini.LoadSources(opts, []byte(raw))
	if err != nil {
		return nil, fmt.Errorf("INI模板解析失败: %w", err)
	}
	seen := map[string]bool{}
	for _, section := range index.Sections() {
		name := section.Name()
		if seen[strings.ToLower(name)] {
			return nil, errors.New("模板存在重复章节")
		}
		seen[strings.ToLower(name)] = true
		opts.UnparseableSections = append(opts.UnparseableSections, name)
	}
	if !seen["proxy group"] || !seen["rule"] {
		return nil, errors.New("模板需要 [Proxy Group] 和 [Rule] 章节")
	}
	file, err := ini.LoadSources(opts, []byte(raw))
	if err != nil {
		return nil, err
	}
	for _, section := range file.Sections() {
		name := strings.ToLower(section.Name())
		if (strings.Contains(name, "proxy") && name != "proxy" && name != "proxy group") || name == "include" {
			return nil, errors.New("模板不允许外部节点提供器或配置包含章节")
		}
		if name == strings.ToLower(ini.DefaultSection) {
			for _, line := range strings.Split(section.Body(), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") {
					return nil, errors.New("配置项必须位于章节内")
				}
			}
		}
	}
	return file, nil
}

func iniCSV(value string) ([]string, error) {
	reader := csv.NewReader(strings.NewReader(value))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	parts, err := reader.Read()
	if err != nil {
		return nil, errors.New("代理组成员格式无效")
	}
	return parts, nil
}

func iniTemplateBody(file *ini.File, name string) string {
	for _, section := range file.Sections() {
		if strings.EqualFold(section.Name(), name) {
			return section.Body()
		}
	}
	return ""
}

func renderINITemplate(raw string, nodes []clientNode, format string) (string, error) {
	file, err := parseINITemplate(raw)
	if err != nil {
		return "", err
	}
	proxyLines, names := []string{}, []string{}
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true}
	for _, node := range nodes {
		proxyLines = append(proxyLines, iniNode(node, format))
		names = append(names, quoteINI(node.Name))
		known[node.Name] = true
	}
	groups := map[string][]string{}
	groupLines := []string{}
	for _, line := range strings.Split(iniTemplateBody(file, "Proxy Group"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			groupLines = append(groupLines, line)
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || known[name] {
			return "", errors.New("代理组名称无效或重复")
		}
		known[name] = true
		groups[name] = []string{}
		value = strings.ReplaceAll(value, "{{PROXY_NODES}}", strings.Join(names, ", "))
		parts, e := iniCSV(value)
		if e != nil {
			return "", e
		}
		if len(parts) < 2 {
			return "", errors.New("代理组至少需要一个成员")
		}
		switch strings.TrimSpace(parts[0]) {
		case "select", "url-test", "fallback", "load-balance", "ssid", "smart":
		default:
			return "", errors.New("不支持的代理组类型")
		}
		for _, part := range parts[1:] {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if known[part] {
				groups[name] = append(groups[name], part)
				continue
			}
			key, _, option := strings.Cut(part, "=")
			if option {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "url", "interval", "tolerance", "timeout", "evaluate-before-use", "persistent", "hidden", "icon", "test-url", "test-timeout", "policy-select-name", "policy-select-index":
				default:
					return "", fmt.Errorf("不支持的代理组选项: %s", key)
				}
			} else {
				groups[name] = append(groups[name], part)
			}
		}
		if len(groups[name]) == 0 {
			return "", errors.New("代理组至少需要一个有效成员")
		}
		groupLines = append(groupLines, name+" = "+value)
	}
	active, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(name string) error {
		if active[name] {
			return errors.New("代理组存在循环引用")
		}
		if done[name] {
			return nil
		}
		active[name] = true
		for _, ref := range groups[name] {
			if !known[ref] {
				return fmt.Errorf("代理组引用不存在: %s", ref)
			}
			if _, ok := groups[ref]; ok {
				if e := visit(ref); e != nil {
					return e
				}
			}
		}
		active[name] = false
		done[name] = true
		return nil
	}
	for name := range groups {
		if err := visit(name); err != nil {
			return "", err
		}
	}
	var out strings.Builder
	hasProxy := false
	for _, section := range file.Sections() {
		name, body := section.Name(), section.Body()
		if strings.EqualFold(name, ini.DefaultSection) {
			if body != "" {
				out.WriteString(body + "\n")
			}
			continue
		}
		switch strings.ToLower(name) {
		case "proxy":
			body = strings.Join(proxyLines, "\n")
			hasProxy = true
		case "proxy group":
			body = strings.Join(groupLines, "\n")
		}
		out.WriteString("[" + name + "]\n" + body + "\n\n")
	}
	if !hasProxy {
		out.WriteString("[Proxy]\n" + strings.Join(proxyLines, "\n") + "\n")
	}
	return out.String(), nil
}

func normalizeTemplateDocument(raw, kind string, version int) (string, []string, error) {
	if kind != "Clash" && kind != "Surge" && kind != "Loon" {
		return "", nil, errors.New("模板类型仅支持Clash、Surge或Loon")
	}
	if strings.TrimSpace(raw) == "" {
		raw = blankTemplate(kind)
	}
	if kind != "Clash" {
		if version == 2 {
			return "", nil, errors.New("V2导入仅支持Clash模板")
		}
		file, err := parseINITemplate(raw)
		if err != nil {
			return "", nil, err
		}
		if strings.TrimSpace(iniTemplateBody(file, "Proxy")) != "" {
			var err error
			raw, err = templateFromSubscription(raw, kind)
			if err != nil {
				return "", nil, err
			}
		}
		return strings.TrimSpace(raw) + "\n", []string{}, nil
	}
	cfg, warnings, err := normalizeTemplate(raw, version)
	if err != nil {
		return "", nil, err
	}
	if providers, ok := cfg["proxy-providers"].(map[string]any); ok && len(providers) > 0 {
		return "", nil, errors.New("订阅模板不允许注入外部节点提供器")
	}
	if len(mapList(cfg["proxies"])) > 0 {
		data, err := yaml.Marshal(cfg)
		if err != nil {
			return "", nil, err
		}
		extracted, err := templateFromSubscription(string(data), "Clash")
		if err != nil {
			return "", nil, err
		}
		return extracted, warnings, nil
	}
	delete(cfg, "proxies")
	rawBytes, err := yaml.Marshal(cfg)
	return string(rawBytes), warnings, err
}

func (a *App) templatePreview(ctx context.Context, content, kind string) (string, error) {
	records, err := a.DB.ListRecords(ctx, "nodes", "")
	if err != nil {
		return "", err
	}
	nodes := []clientNode{}
	names := map[string]int{}
	for _, record := range records {
		node, e := clientNodeFor(record, store.Record{})
		if e == nil {
			node, e = a.relayClient(ctx, record.ID, node)
		}
		if e == nil && compatible(node, strings.ToLower(kind)) {
			names[node.Name]++
			if names[node.Name] > 1 {
				node.Name += fmt.Sprintf(" (%d)", names[node.Name])
			}
			nodes = append(nodes, node)
		}
	}
	if kind != "Clash" {
		if len(nodes) == 0 {
			content = strings.ReplaceAll(content, "{{PROXY_NODES}}", "DIRECT")
		}
		return renderINITemplate(content, nodes, strings.ToLower(kind))
	}
	cfg, _, err := normalizeTemplate(content, 3)
	if err != nil {
		return "", err
	}
	proxies := []any{}
	for _, node := range nodes {
		proxies = append(proxies, clashNode(node))
	}
	cfg["proxies"] = proxies
	cfg, err = expandTemplate(cfg)
	if err != nil {
		return "", err
	}
	data, err := yaml.Marshal(cfg)
	return string(data), err
}

func templateSnapshot(rec store.Record) store.Record {
	return store.Record{Collection: "_documentVersions", ID: newID(), Data: map[string]any{"documentId": rec.ID, "collection": "policies", "version": rec.Version, "content": rec.Data["content"], "type": rec.Data["type"]}}
}

func (a *App) templateManagementAction(ctx context.Context, u store.User, in actionInput) (map[string]any, error) {
	templateMu.Lock()
	defer templateMu.Unlock()
	if in.Action == "template.history" {
		rows, err := a.DB.ListRecords(ctx, "_documentVersions", "")
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, row := range rows {
			if text(row.Data, "documentId") == in.TargetID && text(row.Data, "collection") == "policies" {
				out = append(out, rowOf(row, false))
			}
		}
		return map[string]any{"versions": out}, nil
	}
	if in.Action == "template.default" || in.Action == "template.visibility" {
		rows, err := a.DB.ListRecords(ctx, "policies", "")
		if err != nil {
			return nil, err
		}
		updates := []store.Record{}
		found := false
		kind := ""
		for _, row := range rows {
			if row.ID == in.TargetID {
				kind = templateType(text(row.Data, "type"))
				found = true
			}
		}
		if in.Action == "template.default" && !found {
			return nil, errors.New("模板不存在")
		}
		visibility, _ := in.Params["visibility"].(map[string]any)
		for _, row := range rows {
			if in.Action == "template.default" && templateType(text(row.Data, "type")) == kind {
				row.Data["isDefault"] = row.ID == in.TargetID && in.Params["enabled"] != false
				updates = append(updates, row)
			}
			if in.Action == "template.visibility" {
				if v, ok := visibility[row.ID]; ok {
					visible, ok := v.(bool)
					if !ok {
						return nil, errors.New("可见性必须为布尔值")
					}
					row.Data["userVisible"] = visible
					updates = append(updates, row)
				}
			}
		}
		if len(updates) > 0 {
			if _, err := a.DB.CompareAndSaveRecords(ctx, updates); err != nil {
				return nil, err
			}
		}
		a.audit(ctx, u, in.Action, in.TargetID, nil)
		return map[string]any{"success": true}, nil
	}
	kind := templateType(text(in.Params, "type"))
	if kind == "" {
		return nil, errors.New("不支持的模板类型")
	}
	raw := text(in.Params, "content")
	version := int(number(in.Params, "version"))
	old := store.Record{}
	if in.TargetID != "" {
		var err error
		old, err = a.DB.GetRecord(ctx, "policies", in.TargetID)
		if err != nil {
			return nil, err
		}
		if v := int64(number(in.Params, "recordVersion")); v > 0 && v != old.Version {
			return nil, store.ErrConflict
		}
		if text(in.Params, "type") == "" {
			kind = templateType(text(old.Data, "type"))
		}
	}
	if in.Action == "template.restore" {
		snapshot, err := a.DB.GetRecord(ctx, "_documentVersions", text(in.Params, "versionId"))
		if err != nil {
			return nil, err
		}
		if text(snapshot.Data, "documentId") != in.TargetID || text(snapshot.Data, "collection") != "policies" {
			return nil, errors.New("模板版本归属不匹配")
		}
		raw = text(snapshot.Data, "content")
		version = 3
		if templateType(text(snapshot.Data, "type")) != kind {
			return nil, errors.New("历史模板类型不匹配")
		}
	}
	if source := text(in.Params, "url"); source != "" {
		if _, err := secureOrigin(source); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", source, nil)
		if err != nil {
			return nil, err
		}
		response, err := a.backupHTTP(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		if err != nil || len(data) > 1<<20 {
			return nil, errors.New("远程模板读取失败或超过1MiB")
		}
		raw = string(data)
	}
	if subID := text(in.Params, "subscriptionId"); subID != "" {
		sub, err := a.DB.GetRecord(ctx, "subscriptions", subID)
		if err != nil {
			return nil, err
		}
		records, err := a.subscriptionCandidates(ctx, sub)
		if err != nil {
			return nil, err
		}
		raw, _, _, err = a.renderSubscription(ctx, sub, records, strings.ToLower(kind))
		if err != nil {
			return nil, err
		}
		raw, err = templateFromSubscription(raw, kind)
		if err != nil {
			return nil, err
		}
	}
	content, warnings, err := normalizeTemplateDocument(raw, kind, version)
	if err != nil {
		return nil, err
	}
	preview, err := a.templatePreview(ctx, content, kind)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"content": content, "preview": preview, "warnings": warnings, "type": kind}
	if in.Action == "template.import" || in.Action == "template.restore" {
		if old.ID != "" && templateType(text(old.Data, "type")) != kind {
			return nil, errors.New("已保存模板不可更改类型，请创建新模板")
		}
		id := in.TargetID
		if id == "" {
			id = newID()
		}
		data := clone(old.Data)
		if data == nil {
			data = map[string]any{}
		}
		data["name"] = defaultText(in.Params, "name", defaultText(old.Data, "name", "导入模板"))
		data["content"] = content
		delete(data, "sourceContent")
		data["type"] = kind
		data["version"] = 3
		data["warnings"] = warnings
		data["importedAt"] = time.Now().UTC()
		rec := store.Record{Collection: "policies", ID: id, Version: old.Version, Data: data}
		changes := []store.Record{rec}
		if old.ID != "" {
			changes = append(changes, templateSnapshot(old))
		}
		saved, err := a.DB.CompareAndSaveRecords(ctx, changes)
		if err != nil {
			return nil, err
		}
		result["row"] = rowOf(saved[0], false)
		a.audit(ctx, u, in.Action, id, nil)
	}
	return result, nil
}

func templateFromSubscription(raw, kind string) (string, error) {
	if kind != "Clash" {
		file, err := parseINITemplate(raw)
		if err != nil {
			return "", err
		}
		proxyNames := map[string]bool{}
		proxies, err := ini.LoadSources(ini.LoadOptions{IgnoreInlineComment: true, KeyValueDelimiters: "="}, []byte(iniTemplateBody(file, "Proxy")))
		if err != nil {
			return "", fmt.Errorf("节点章节解析失败: %w", err)
		}
		for _, key := range proxies.Section(ini.DefaultSection).Keys() {
			proxyNames[key.Name()] = true
		}
		var out strings.Builder
		for _, section := range file.Sections() {
			if strings.EqualFold(section.Name(), ini.DefaultSection) || strings.EqualFold(section.Name(), "Proxy") {
				continue
			}
			body := section.Body()
			if strings.EqualFold(section.Name(), "Proxy Group") {
				lines := []string{}
				for _, line := range strings.Split(body, "\n") {
					name, value, ok := strings.Cut(line, "=")
					if !ok {
						lines = append(lines, line)
						continue
					}
					parts, err := iniCSV(value)
					if err != nil {
						return "", err
					}
					kept := []string{parts[0]}
					inserted := false
					for _, part := range parts[1:] {
						if proxyNames[strings.TrimSpace(part)] {
							if !inserted {
								kept = append(kept, "{{PROXY_NODES}}")
								inserted = true
							}
						} else {
							kept = append(kept, part)
						}
					}
					lines = append(lines, strings.TrimSpace(name)+" = "+strings.Join(kept, ", "))
				}
				body = strings.Join(lines, "\n")
			}
			out.WriteString("[" + section.Name() + "]\n" + body + "\n\n")
		}
		return out.String(), nil
	}
	cfg, _, err := normalizeTemplate(raw, 3)
	if err != nil {
		return "", err
	}
	names := map[string]bool{}
	for _, node := range mapList(cfg["proxies"]) {
		names[text(node, "name")] = true
	}
	delete(cfg, "proxies")
	delete(cfg, "proxy-providers")
	delete(cfg, "secret")
	delete(cfg, "external-controller")
	for _, group := range mapList(cfg["proxy-groups"]) {
		refs := []string{}
		include := false
		for _, ref := range stringList(group["proxies"]) {
			if names[ref] {
				include = true
			} else {
				refs = append(refs, ref)
			}
		}
		group["proxies"] = refs
		if include {
			group["include-all-proxies"] = true
		}
		delete(group, "use")
	}
	data, err := yaml.Marshal(cfg)
	return string(data), err
}

func (a *App) selectedTemplate(ctx context.Context, sub store.Record, format string) (store.Record, error) {
	if boolean(sub.Data, "skipTemplates") {
		return store.Record{}, nil
	}
	if id := text(sub.Data, "templateId"); id != "" {
		rec, err := a.DB.GetRecord(ctx, "policies", id)
		if err != nil {
			return rec, errors.New("订阅模板不存在")
		}
		if templateMatches(rec.Data, format) {
			return rec, nil
		}
	}
	if planID := text(sub.Data, "planId"); planID != "" {
		plan, err := a.DB.GetRecord(ctx, "plans", planID)
		if err != nil {
			return store.Record{}, err
		}
		if id := planTemplateID(plan.Data, format); id != "" {
			rec, err := a.DB.GetRecord(ctx, "policies", id)
			if err != nil || !templateMatches(rec.Data, format) {
				return store.Record{}, errors.New("套餐模板不存在或类型不匹配")
			}
			return rec, nil
		}
	}
	rows, err := a.DB.ListRecords(ctx, "policies", "")
	if err != nil {
		return store.Record{}, err
	}
	for _, row := range rows {
		if boolean(row.Data, "isDefault") && templateMatches(row.Data, format) {
			return row, nil
		}
	}
	return store.Record{}, nil
}

func (a *App) templateOptions(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.ListRecords(r.Context(), "policies", "")
	if err != nil {
		fail(w, 500, "storage_error", "读取模板失败")
		return
	}
	result := []any{}
	for _, row := range rows {
		if current(r).Role == "admin" || boolean(row.Data, "userVisible") {
			result = append(result, map[string]any{"id": row.ID, "name": row.Data["name"], "type": templateType(text(row.Data, "type")), "isDefault": boolean(row.Data, "isDefault"), "userVisible": boolean(row.Data, "userVisible")})
		}
	}
	respond(w, 200, map[string]any{"templates": result})
}

func (a *App) requestedTemplate(r *http.Request, sub store.Record, format string) (store.Record, error) {
	id := r.URL.Query().Get("template")
	if id == "" {
		return sub, nil
	}
	rec, err := a.DB.GetRecord(r.Context(), "policies", id)
	if err != nil || !templateMatches(rec.Data, format) {
		return sub, errors.New("模板不存在或与客户端格式不匹配")
	}
	if !boolean(rec.Data, "userVisible") {
		return sub, errors.New("此模板未开放给用户")
	}
	sub.Data = clone(sub.Data)
	if sub.Data == nil {
		sub.Data = map[string]any{}
	}
	sub.Data["templateId"] = id
	return sub, nil
}

func (a *App) templateDeleteCheck(ctx context.Context, id string) error {
	for _, collection := range []string{"plans", "subscriptions", "rules", generatedSubscriptionCollection} {
		rows, err := a.DB.ListRecords(ctx, collection, "")
		if err != nil {
			return err
		}
		for _, row := range rows {
			if collection == generatedSubscriptionCollection && (boolean(row.Data, "revoked") || !time.Now().Before(dateTime(text(row.Data, "expiresAt")))) {
				continue
			}
			if text(row.Data, "templateId") == id || collection == "plans" && (planTemplateID(row.Data, "clash") == id || planTemplateID(row.Data, "surge") == id || planTemplateID(row.Data, "loon") == id) {
				return fmt.Errorf("模板仍被 %s 使用，请先解除关联", defaultText(row.Data, "name", row.ID))
			}
		}
	}
	return nil
}
