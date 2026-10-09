package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
)

const firewallMaxRevision int64 = 1<<53 - 1

var firewallIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var errFirewallDedicatedAPI = errors.New("防火墙规则须通过服务器安全页面读取当前版本后保存或刷新，不能直接下发或重试旧指令")

type firewallRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	Port         int      `json:"port"`
	AllowedCIDRs []string `json:"allowedCidrs"`
}

type firewallTarget struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func (a *App) firewallCapable(serverID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.peers[serverID]
	return p != nil && p.Capabilities["firewall_allowlist"]
}

func (a *App) requireFirewallCapability(serverID string) error {
	if !a.firewallCapable(serverID) {
		return errors.New("尚未收到 Agent 的防火墙白名单能力，请先升级 Agent 并等待连接上报")
	}
	return nil
}

func firewallRules(value any) ([]firewallRule, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var rules []firewallRule
	if err = json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []firewallRule{}
	}
	return rules, nil
}

func (a *App) firewallPolicy(ctx context.Context, serverID string) (store.Record, error) {
	policy, err := a.DB.GetRecord(ctx, "_firewallPolicies", serverID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Record{Collection: "_firewallPolicies", ID: serverID, Data: map[string]any{"revision": int64(0), "rules": []firewallRule{}}}, nil
	}
	return policy, err
}

func firewallRevision(data map[string]any) int64 {
	n := number(data, "revision")
	if n < 0 || n > float64(firewallMaxRevision) || n != float64(int64(n)) {
		return -1
	}
	return int64(n)
}

func firewallReservedPorts(server store.Record) map[int]bool {
	ports := map[int]bool{22: true, 23889: true}
	if port := int(number(server.Data, "agentPort")); port > 0 {
		ports[port] = true
	}
	if u, err := url.Parse(text(server.Data, "agentUrl")); err == nil && u.Host != "" {
		port, _ := strconv.Atoi(u.Port())
		if port == 0 && u.Scheme == "https" {
			port = 443
		}
		if port == 0 && u.Scheme == "http" {
			port = 80
		}
		if port > 0 {
			ports[port] = true
		}
	}
	return ports
}

func (a *App) firewallTargets(ctx context.Context, server store.Record) ([]firewallTarget, error) {
	out := []firewallTarget{}
	if !nativeServer(server) {
		return out, nil
	}
	rows, err := a.DB.ListRecords(ctx, "inbounds", "")
	if err != nil {
		return nil, err
	}
	reserved := firewallReservedPorts(server)
	portCounts := map[int]int{}
	for _, row := range rows {
		if text(row.Data, "serverId") == server.ID && !disabledStatus(row.Data) {
			portCounts[int(number(row.Data, "port"))]++
		}
	}
	for _, row := range rows {
		if text(row.Data, "serverId") != server.ID || disabledStatus(row.Data) || validateRealityInboundProfile(row.Data) != nil {
			continue
		}
		listen := defaultText(row.Data, "listen", "0.0.0.0")
		if addr, err := netip.ParseAddr(listen); err != nil || !addr.IsUnspecified() || addr.Zone() != "" || addr.Is4In6() {
			continue
		}
		port := int(number(row.Data, "port"))
		if port < 1 || port > 65535 || float64(port) != number(row.Data, "port") || reserved[port] || portCounts[port] != 1 {
			continue
		}
		out = append(out, firewallTarget{ID: row.ID, Name: defaultText(row.Data, "name", text(row.Data, "tag")), Protocol: "tcp", Port: port})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func normalizeFirewallRules(rules []firewallRule, targets []firewallTarget) ([]firewallRule, error) {
	if len(rules) > 64 {
		return nil, errors.New("最多配置 64 条防火墙规则")
	}
	ports := map[int]bool{}
	for _, target := range targets {
		if target.Protocol == "tcp" {
			ports[target.Port] = true
		}
	}
	seenID, seenPort := map[string]bool{}, map[int]bool{}
	out := make([]firewallRule, 0, len(rules))
	for _, rule := range rules {
		if !firewallIDPattern.MatchString(rule.ID) || seenID[rule.ID] {
			return nil, errors.New("规则标识须为 1–64 位字母、数字、下划线或连字符且不能重复")
		}
		rule.Name = strings.TrimSpace(rule.Name)
		if utf8.RuneCountInString(rule.Name) > 100 || strings.IndexFunc(rule.Name, unicode.IsControl) >= 0 {
			return nil, errors.New("规则名称不能超过 100 字或含控制字符")
		}
		if rule.Protocol != "tcp" || rule.Port < 1 || rule.Port > 65535 || !ports[rule.Port] || seenPort[rule.Port] {
			return nil, errors.New("仅可选择当前已启用的 TCP REALITY 业务端口，端口不能重复，禁止管理端口")
		}
		if len(rule.AllowedCIDRs) == 0 || len(rule.AllowedCIDRs) > 128 {
			return nil, errors.New("每条规则须填写 1–128 个允许访问的 IP 或 CIDR；取消保护请删除规则")
		}
		cidrs := make([]string, 0, len(rule.AllowedCIDRs))
		seen := map[string]bool{}
		for _, raw := range rule.AllowedCIDRs {
			raw = strings.TrimSpace(raw)
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				addr, parseErr := netip.ParseAddr(raw)
				if parseErr != nil {
					return nil, errors.New("允许地址必须为有效 IPv4、IPv6 或 CIDR")
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return nil, errors.New("允许地址不支持作用域标识或 IPv4 映射 IPv6")
			}
			addr, base := prefix.Addr(), prefix.Masked().Addr()
			if prefix.Bits() == 0 || !addr.IsGlobalUnicast() || addr.IsLoopback() || !base.IsGlobalUnicast() || base.IsLoopback() {
				return nil, errors.New("允许地址须为具体单播 IP 或网段，不能使用全网、回环、未指定或组播地址")
			}
			canonical := prefix.Masked().String()
			if !seen[canonical] {
				cidrs = append(cidrs, canonical)
				seen[canonical] = true
			}
		}
		sort.Strings(cidrs)
		rule.AllowedCIDRs = cidrs
		seenID[rule.ID], seenPort[rule.Port] = true, true
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func sameFirewallRules(first, second any) bool {
	if first == nil || second == nil {
		return false
	}
	a, errA := firewallRules(first)
	b, errB := firewallRules(second)
	if errA != nil || errB != nil {
		return false
	}
	for i := range a {
		sort.Strings(a[i].AllowedCIDRs)
	}
	for i := range b {
		sort.Strings(b[i].AllowedCIDRs)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].ID < a[j].ID })
	sort.Slice(b, func(i, j int) bool { return b[i].ID < b[j].ID })
	return reflect.DeepEqual(a, b)
}

func (a *App) firewallObserved(ctx context.Context, serverID string) map[string]any {
	var newest map[string]any
	var newestAt time.Time
	consider := func(value map[string]any) {
		at, err := time.Parse(time.RFC3339Nano, text(value, "checkedAt"))
		if value == nil || err != nil || at.After(time.Now().Add(90*time.Second)) || !at.After(newestAt) {
			return
		}
		newest, newestAt = clone(value), at
	}
	if rec, err := a.DB.GetRecord(ctx, "_firewallObserved", serverID); err == nil {
		consider(rec.Data)
	}
	if rec, err := a.DB.GetRecord(ctx, "_observations", serverID); err == nil {
		if obs, ok := rec.Data["network_firewall"].(map[string]any); ok {
			consider(obs)
		}
	}
	return newest
}

func (a *App) firewallState(ctx context.Context, server store.Record) (map[string]any, error) {
	policy, err := a.firewallPolicy(ctx, server.ID)
	if err != nil {
		return nil, err
	}
	rules, err := firewallRules(policy.Data["rules"])
	if err != nil {
		return nil, err
	}
	targets, err := a.firewallTargets(ctx, server)
	if err != nil {
		return nil, err
	}
	var taskInfo any
	task, latestTaskErr := a.DB.GetTask(ctx, text(policy.Data, "taskId"))
	if latestTaskErr == nil {
		taskInfo = map[string]any{"id": task.ID, "status": task.Status, "error": task.Error, "kind": task.Kind}
	}
	var observed any
	if status := a.firewallObserved(ctx, server.ID); status != nil {
		applyTask, taskErr := a.DB.GetTask(ctx, text(policy.Data, "applyTaskId"))
		matches := firewallRevision(status) == firewallRevision(policy.Data) && sameFirewallRules(status["rules"], rules)
		status["applied"] = matches && text(status, "backend") == "nftables" && boolean(status, "applied") && boolean(status, "supported") && taskErr == nil && applyTask.Status == "success" && latestTaskErr == nil && task.Status == "success"
		status["matchesDesired"] = matches
		observed = status
	}
	return map[string]any{"serverId": server.ID, "revision": firewallRevision(policy.Data), "rules": rules, "targets": targets, "capable": nativeServer(server) && a.firewallCapable(server.ID), "task": taskInfo, "observed": observed}, nil
}

func (a *App) firewallGet(w http.ResponseWriter, r *http.Request) {
	server, err := a.DB.GetRecord(r.Context(), "servers", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	state, err := a.firewallState(r.Context(), server)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取防火墙规则")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, state)
}

func (a *App) firewallPut(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Revision *int64          `json:"revision"`
		Rules    *[]firewallRule `json:"rules"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Revision == nil || *input.Revision < 0 || *input.Revision >= firewallMaxRevision || input.Rules == nil {
		fail(w, 400, "invalid_firewall", "请携带有效规则版本和规则列表，清空保护须明确提交空列表")
		return
	}
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	server, err := a.DB.GetRecord(r.Context(), "servers", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	if !nativeServer(server) || disabledStatus(server.Data) {
		fail(w, 409, "unsupported_server", "请选择已启用的内嵌 Xray Agent 服务器")
		return
	}
	if err = a.requireFirewallCapability(server.ID); err != nil {
		fail(w, 409, "agent_upgrade_required", err.Error())
		return
	}
	policy, err := a.firewallPolicy(r.Context(), server.ID)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取防火墙规则")
		return
	}
	if *input.Revision != firewallRevision(policy.Data) {
		fail(w, 409, "conflict", "防火墙规则已改变，请刷新后重试")
		return
	}
	targets, err := a.firewallTargets(r.Context(), server)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取业务端口")
		return
	}
	rules, err := normalizeFirewallRules(*input.Rules, targets)
	if err != nil {
		fail(w, 400, "invalid_firewall", err.Error())
		return
	}
	revision := *input.Revision + 1
	command := agentwire.Command{ID: newID(), Action: "network.firewall.apply", Params: map[string]any{"revision": revision, "rules": rules}}
	ports := map[int]bool{}
	for _, port := range firewallGuardedPorts(policy.Data) {
		ports[port] = true
	}
	for _, rule := range rules {
		ports[rule.Port] = true
	}
	guarded := []int{}
	for port := range ports {
		guarded = append(guarded, port)
	}
	sort.Ints(guarded)
	policy.Data = map[string]any{"revision": revision, "rules": rules, "taskId": command.ID, "applyTaskId": command.ID, "guardedPorts": guarded}
	if err = a.createFirewallTask(r.Context(), current(r), server.ID, command, policy); err != nil {
		fail(w, 409, "conflict", "规则和任务均未提交，请刷新后重试")
		return
	}
	a.firewallMutationResponse(w, r, server)
}

func (a *App) firewallRefresh(w http.ResponseWriter, r *http.Request) {
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	server, err := a.DB.GetRecord(r.Context(), "servers", r.PathValue("id"))
	if err != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	if !nativeServer(server) || disabledStatus(server.Data) {
		fail(w, 409, "unsupported_server", "请选择已启用的内嵌 Xray Agent 服务器")
		return
	}
	if err = a.requireFirewallCapability(server.ID); err != nil {
		fail(w, 409, "agent_upgrade_required", err.Error())
		return
	}
	policy, err := a.firewallPolicy(r.Context(), server.ID)
	if err != nil {
		fail(w, 503, "storage_error", "无法读取防火墙规则")
		return
	}
	command := agentwire.Command{ID: newID(), Action: "network.firewall.status", Params: map[string]any{}}
	policy.Data["taskId"] = command.ID
	if err = a.createFirewallTask(r.Context(), current(r), server.ID, command, policy); err != nil {
		fail(w, 409, "conflict", "状态任务未提交，请刷新后重试")
		return
	}
	a.firewallMutationResponse(w, r, server)
}

func (a *App) createFirewallTask(ctx context.Context, actor store.User, serverID string, command agentwire.Command, policy store.Record) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	task := store.Task{ID: command.ID, ServerID: serverID, ActorID: actor.ID, Kind: command.Action, Status: "queued", Input: raw}
	if _, err = a.DB.CreateTaskWithChanges(ctx, task, []store.Record{policy}, nil); err != nil {
		return err
	}
	a.audit(ctx, actor, command.Action, serverID, map[string]any{"taskId": command.ID, "revision": firewallRevision(policy.Data)})
	return nil
}

func (a *App) firewallMutationResponse(w http.ResponseWriter, r *http.Request, server store.Record) {
	state, err := a.firewallState(r.Context(), server)
	if err != nil {
		fail(w, 503, "storage_error", "任务已创建，但无法读取当前状态，请刷新核对")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 202, state)
}

func (a *App) validateFirewallTask(ctx context.Context, task store.Task, command agentwire.Command) error {
	if !strings.HasPrefix(command.Action, "network.firewall.") {
		return nil
	}
	if command.Action != task.Kind || command.ID != task.ID {
		return errFirewallDedicatedAPI
	}
	if err := a.requireFirewallCapability(task.ServerID); err != nil {
		return err
	}
	policy, err := a.firewallPolicy(ctx, task.ServerID)
	if err != nil {
		return err
	}
	if command.Action == "network.firewall.status" {
		if task.ID != text(policy.Data, "taskId") || len(command.Params) != 0 {
			return errFirewallDedicatedAPI
		}
		return nil
	}
	if command.Action != "network.firewall.apply" || task.ID != text(policy.Data, "applyTaskId") || firewallRevision(command.Params) <= 0 || firewallRevision(command.Params) != firewallRevision(policy.Data) || !sameFirewallRules(command.Params["rules"], policy.Data["rules"]) {
		return errors.New("防火墙任务已被新版本替代，请通过服务器安全页面重新保存当前规则")
	}
	server, err := a.DB.GetRecord(ctx, "servers", task.ServerID)
	if err != nil || disabledStatus(server.Data) {
		return errors.New("服务器不存在或已停用")
	}
	targets, err := a.firewallTargets(ctx, server)
	if err != nil {
		return err
	}
	rules, err := firewallRules(command.Params["rules"])
	if err != nil {
		return err
	}
	normalized, err := normalizeFirewallRules(rules, targets)
	if err != nil {
		return err
	}
	if !sameFirewallRules(normalized, rules) {
		return errors.New("防火墙规则不是当前规范格式，请重新保存")
	}
	return nil
}

func (a *App) finishFirewallTask(ctx context.Context, task store.Task, result agentwire.Result) {
	if task.Kind != "network.firewall.apply" && task.Kind != "network.firewall.status" {
		return
	}
	a.managedNodeMu.Lock()
	defer a.managedNodeMu.Unlock()
	policy, err := a.firewallPolicy(ctx, task.ServerID)
	if err != nil || task.Kind == "network.firewall.apply" && text(policy.Data, "applyTaskId") != task.ID || task.Kind == "network.firewall.status" && text(policy.Data, "taskId") != task.ID {
		return
	}
	if result.Status != "success" || result.Data == nil {
		return
	}
	checkedAt, err := time.Parse(time.RFC3339Nano, text(result.Data, "checkedAt"))
	if err != nil || checkedAt.After(time.Now().Add(90*time.Second)) {
		return
	}
	old, err := a.DB.GetRecord(ctx, "_firewallObserved", task.ServerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return
	}
	if previousAt, err := time.Parse(time.RFC3339Nano, text(old.Data, "checkedAt")); err == nil && checkedAt.Before(previousAt) {
		return
	}
	observed := store.Record{Collection: "_firewallObserved", ID: task.ServerID, Version: old.Version, Data: clone(result.Data)}
	if _, err = a.DB.SaveRecord(ctx, observed); err != nil {
		return
	}
	// Until removal is confirmed, keep the old protected ports locked against
	// inbound edits; queued removal is not evidence that the kernel is open.
	if text(result.Data, "backend") == "nftables" && boolean(result.Data, "applied") && boolean(result.Data, "supported") && firewallRevision(result.Data) == firewallRevision(policy.Data) && sameFirewallRules(result.Data["rules"], policy.Data["rules"]) {
		applyTask, err := a.DB.GetTask(ctx, text(policy.Data, "applyTaskId"))
		if err != nil || applyTask.Status != "success" {
			return
		}
		rules, err := firewallRules(policy.Data["rules"])
		if err != nil {
			return
		}
		ports := []int{}
		for _, rule := range rules {
			ports = append(ports, rule.Port)
		}
		sort.Ints(ports)
		policy.Data["guardedPorts"] = ports
		_, _ = a.DB.SaveRecord(ctx, policy)
	}
}

func firewallGuardedPorts(data map[string]any) []int {
	ports := map[int]bool{}
	raw, _ := json.Marshal(data["guardedPorts"])
	var previous []int
	_ = json.Unmarshal(raw, &previous)
	for _, port := range previous {
		ports[port] = true
	}
	rules, _ := firewallRules(data["rules"])
	for _, rule := range rules {
		ports[rule.Port] = true
	}
	out := []int{}
	for port := range ports {
		out = append(out, port)
	}
	return out
}

func (a *App) firewallInboundChange(ctx context.Context, previous store.Record, next map[string]any) error {
	if previous.ID == "" {
		return nil
	}
	policy, err := a.firewallPolicy(ctx, text(previous.Data, "serverId"))
	if err != nil {
		return err
	}
	protected := false
	for _, port := range firewallGuardedPorts(policy.Data) {
		if port == int(number(previous.Data, "port")) {
			protected = true
		}
	}
	if !protected {
		return nil
	}
	if next == nil || disabledStatus(next) {
		return errors.New("该业务端口仍受防火墙保护，请先删除白名单规则并等待 Agent 确认，再停用或删除入站")
	}
	if !reflect.DeepEqual(firewallInboundBinding(next), firewallInboundBinding(previous.Data)) {
		return errors.New("受防火墙保护的入站不能更改服务器、标识、端口或监听方式，请先删除对应规则并等待执行成功")
	}
	return nil
}

// Old managed records omit defaults that the editor fills on save. Compare
// effective listener identity so harmless normalization is not a port change.
func firewallInboundBinding(row map[string]any) map[string]any {
	network, security := inboundTransport(row)
	if validateRealityInboundProfile(row) == nil {
		network, security = "tcp", "reality"
	}
	listen := strings.TrimSpace(defaultText(row, "listen", "0.0.0.0"))
	if address, err := netip.ParseAddr(listen); err == nil {
		listen = address.String()
	}
	return map[string]any{"serverId": text(row, "serverId"), "tag": text(row, "tag"), "port": number(row, "port"), "protocol": strings.ToLower(strings.TrimSpace(text(row, "protocol"))), "network": network, "security": security, "listen": listen}
}
