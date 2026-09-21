package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"github.com/coder/websocket"
)

func (a *App) enrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, e := a.DB.GetRecord(r.Context(), "servers", id)
	if e != nil {
		fail(w, 404, "not_found", "服务器不存在")
		return
	}
	if !nativeServer(rec) {
		fail(w, 409, "unsupported_connection", errUnsupportedServerConnection.Error())
		return
	}
	credentials, e := a.DB.GetRecord(r.Context(), "_agentCredentials", id)
	if e != nil {
		fail(w, 409, "credentials_missing", "服务器接入凭据缺失，请重置凭据")
		return
	}
	if mode := text(rec.Data, "xray_mode"); mode != "" && mode != "embedded" {
		fail(w, 409, "unsupported_core", "当前仅支持内嵌 Xray，请更新服务器配置后重新接入")
		return
	}
	cfg := a.agentInstallConfig(rec, credentials)
	a.audit(r.Context(), current(r), "server.enrollment.read", id, nil)
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, map[string]any{"serverId": id, "serverToken": credentials.Data["serverToken"], "agentToken": credentials.Data["agentToken"], "masterPublicKey": a.MasterPublic, "masterUrl": a.Config.PublicURL, "config": cfg, "installation": a.installationOffer(rec, credentials)})
}
func (a *App) acceptReport(ctx context.Context, report agentwire.Report, transport string) (agentwire.Reply, error) {
	if transport != "WebSocket" && transport != "HTTP" && transport != "Pull" {
		return agentwire.Reply{}, errors.New("unsupported agent transport")
	}
	now := time.Now()
	if report.Timestamp < now.Add(-90*time.Second).Unix() || report.Timestamp > now.Add(90*time.Second).Unix() {
		return agentwire.Reply{}, errors.New("agent clock outside accepted window")
	}
	if report.Mode == "speedtest" {
		return a.acceptHomeReport(ctx, report, transport)
	}
	if report.Mode != "embedded" {
		return agentwire.Reply{}, errors.New("only embedded Xray is supported; reinstall the Agent with embedded configuration")
	}
	credentials, e := a.DB.GetRecord(ctx, "_agentCredentials", report.ServerID)
	if e != nil || !constant(text(credentials.Data, "serverToken"), report.Token) {
		return agentwire.Reply{}, errors.New("agent identity rejected")
	}
	server, e := a.DB.GetRecord(ctx, "servers", report.ServerID)
	if e != nil {
		return agentwire.Reply{}, errors.New("server removed")
	}
	if !nativeServer(server) {
		return agentwire.Reply{}, errUnsupportedServerConnection
	}
	if disabledStatus(server.Data) {
		a.mu.Lock()
		delete(a.peers, report.ServerID)
		a.mu.Unlock()
		return agentwire.Reply{}, errors.New("server disabled")
	}
	a.mu.Lock()
	previousPeer := a.peers[report.ServerID]
	directActive := transport == "Pull" && serverConnectionMode(server) == "auto" && previousPeer != nil && previousPeer.Transport == "HTTP" && now.Sub(previousPeer.LastSeen) < 15*time.Second
	if !directActive {
		a.peers[report.ServerID] = &peer{LastSeen: now, Transport: transport, Version: report.Version, Mode: report.Mode, ConnectionMode: report.ConnectionMode, Capabilities: report.Capabilities}
	}
	a.mu.Unlock()
	if report.Observation != nil {
		// Older Agents may still send host metrics. Only retain management state;
		// Komari is the sole source of host monitoring and its history.
		state := map[string]any{}
		for _, key := range []string{"core", "vision_splice", "network_forward", "mihomo", "xray_stats", "agent_update"} {
			if value, ok := report.Observation[key]; ok {
				state[key] = value
			}
		}
		report.Observation = state
		previous, _ := a.DB.GetRecord(ctx, "_observations", report.ServerID)
		_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_observations", ID: report.ServerID, Data: report.Observation, Version: previous.Version})
		if stats, ok := report.Observation["xray_stats"].(map[string]any); ok {
			a.accountStats(ctx, report.ServerID, stats)
		}
		if forwards, ok := report.Observation["network_forward"].(map[string]any); ok {
			a.accountForwards(ctx, report.ServerID, forwards)
		}
	}
	for _, result := range report.Results {
		a.finishTask(ctx, report.ServerID, result)
	}
	if report.Capabilities["core_config"] {
		a.syncXrayCache(ctx, report.ServerID, now)
	}
	reply := agentwire.Reply{Interval: 5}
	desired := serverConnectionMode(server)
	if report.Capabilities["connection_modes"] {
		reply.ConnectionMode, reply.ListenAddress = desired, agentListenAddress(server)
	}
	// Acknowledge prior results before switching, without dispatching more work.
	if directActive || transport == "HTTP" || (desired != "auto" && !strings.EqualFold(transport, desired)) || (report.ConnectionMode != "" && report.ConnectionMode != desired) {
		return reply, nil
	}
	a.agentDispatchMu.Lock()
	defer a.agentDispatchMu.Unlock()
	tasks, e := a.DB.ListPendingTasks(ctx, report.ServerID, 100)
	if e != nil {
		return agentwire.Reply{}, e
	}
	commands := []agentwire.Command{}
	for _, task := range tasks {
		if task.Status != "queued" || !a.permitDispatch(ctx, task) {
			continue
		}
		var cmd agentwire.Command
		if json.Unmarshal(task.Input, &cmd) != nil {
			continue
		}
		task.Status = "running"
		task.UpdatedAt = now
		if _, e = a.DB.SaveTask(ctx, task); e != nil {
			continue
		}
		commands = append(commands, cmd)
		if len(commands) >= 16 {
			break
		}
	}
	reply.Commands = commands
	return reply, nil
}
func (a *App) finishTask(ctx context.Context, serverID string, result agentwire.Result) bool {
	task, e := a.DB.GetTask(ctx, result.ID)
	if e != nil || task.ServerID != serverID || (task.Status != "running" && task.Status != "unknown") {
		return false
	}
	switch result.Status {
	case "success", "failed", "unsupported":
	default:
		result.Status = "failed"
		result.Error = "Agent returned invalid result status"
	}
	task.Status = result.Status
	task.Error = result.Error
	task.Result, _ = json.Marshal(result.Data)
	task.UpdatedAt = time.Now()
	if _, e = a.DB.SaveTask(ctx, task); e != nil {
		return false
	}
	a.finishAuxiliaryCompile(ctx, task)
	a.finishXrayCache(ctx, task, result)
	if (result.Status == "failed" || result.Status == "unsupported") && task.ActorID != "system:xray-cache" && !strings.HasPrefix(task.Kind, "logs.") {
		a.emitEvent(ctx, "task.failed", "", task.ID, "任务 "+task.Kind+" 执行失败，请登录主控查看详情。", map[string]any{"serverId": serverID, "status": result.Status})
	}
	if result.Status == "success" && result.Data != nil {
		if task.Kind == "network.quality" {
			a.recordNetworkQuality(ctx, task, result.Data)
		}
		if task.Kind == "network.forward.status" {
			a.accountForwards(ctx, serverID, result.Data)
		}
		if task.Kind == "core.stats" {
			a.accountStats(ctx, serverID, result.Data)
		}
		if cfg, ok := result.Data["config"].(map[string]any); ok && task.ActorID != "system:xray-cache" {
			_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_configHistory", ID: newID(), Data: map[string]any{"serverId": serverID, "source": "agent", "config": cfg, "taskId": task.ID}})
		}
	}
	return true
}
func (a *App) agentWS(w http.ResponseWriter, r *http.Request) {
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: a.Config.AllowedOrigins})
	if e != nil {
		return
	}
	defer conn.CloseNow()
	if !a.trackSocket(conn) {
		return
	}
	defer a.forgetSocket(conn)
	conn.SetReadLimit(agentwire.MaxPacket * 2)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	firstCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	_, raw, e := conn.Read(firstCtx)
	stop()
	if e != nil {
		return
	}
	var hello agentwire.Hello
	if json.Unmarshal(raw, &hello) != nil {
		return
	}
	a.stateMu.RLock()
	private := a.MasterPrivate
	a.stateMu.RUnlock()
	channel, e := agentwire.NewServer(private, hello.PublicKey)
	if e != nil {
		return
	}
	var report agentwire.Report
	if channel.Open(hello.Packet, &report) != nil {
		return
	}
	serverID := report.ServerID
	a.mu.Lock()
	_, seen := a.handshakes[hello.PublicKey]
	if !seen {
		a.handshakes[hello.PublicKey] = time.Now()
	}
	a.mu.Unlock()
	if seen {
		return
	}
	for {
		if report.ServerID != serverID {
			return
		}
		a.stateMu.RLock()
		var reply agentwire.Reply
		var e error
		if private != a.MasterPrivate {
			e = errors.New("master identity changed")
		} else {
			reply, e = a.acceptReport(ctx, report, "WebSocket")
		}
		a.stateMu.RUnlock()
		if e != nil {
			packet, _ := channel.Seal(agentwire.Reply{Error: e.Error()})
			raw, _ := json.Marshal(packet)
			_ = conn.Write(ctx, websocket.MessageText, raw)
			return
		}
		packet, e := channel.Seal(reply)
		if e != nil {
			return
		}
		raw, e = json.Marshal(packet)
		if e != nil {
			return
		}
		ioCtx, done := context.WithTimeout(ctx, 30*time.Second)
		e = conn.Write(ioCtx, websocket.MessageText, raw)
		done()
		if e != nil {
			return
		}
		ioCtx, done = context.WithTimeout(ctx, 120*time.Second)
		_, raw, e = conn.Read(ioCtx)
		done()
		if e != nil {
			return
		}
		var incoming agentwire.Packet
		if json.Unmarshal(raw, &incoming) != nil {
			return
		}
		report = agentwire.Report{}
		if channel.Open(incoming, &report) != nil {
			return
		}
	}
}
func (a *App) queue(ctx context.Context, u store.User, serverID, action string, params map[string]any) (store.Task, error) {
	server, e := a.DB.GetRecord(ctx, "servers", serverID)
	if e != nil {
		return store.Task{}, e
	}
	if !nativeServer(server) {
		return store.Task{}, errUnsupportedServerConnection
	}
	if retiredAgentAction(action) {
		return store.Task{}, errors.New("此动作已不受支持")
	}
	cmd := agentwire.Command{ID: newID(), Action: action, Params: params}
	input, e := json.Marshal(cmd)
	if e != nil {
		return store.Task{}, e
	}
	task := store.Task{ID: cmd.ID, ServerID: serverID, ActorID: u.ID, Kind: action, Status: "queued", Input: input, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	task, e = a.DB.SaveTask(ctx, task)
	if e == nil && !strings.HasPrefix(action, "logs.") {
		a.audit(ctx, u, "agent.command.queued", serverID, map[string]any{"taskId": task.ID, "action": action})
	}
	return task, e
}
func (a *App) maintenance(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.maintenanceTick(ctx)
		}
	}
}
func (a *App) maintenanceTick(ctx context.Context) {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	a.mu.Lock()
	unavailable := a.recoveryRequired || a.closing
	for k, t := range a.handshakes {
		if time.Since(t) > 3*time.Minute {
			delete(a.handshakes, k)
		}
	}
	a.mu.Unlock()
	if unavailable {
		return
	}
	tasks, e := a.DB.ListRunningTasks(ctx, "", 500)
	if e == nil {
		for _, task := range tasks {
			if task.Status == "running" && time.Since(task.UpdatedAt) > 2*time.Minute {
				task.Status = "unknown"
				task.Error = "节点执行结果未返回，请检查实际状态后重试"
				task.UpdatedAt = time.Now()
				_, _ = a.DB.SaveTask(ctx, task)
			}
		}
	}
	a.retireUnusedInitialPolicyTasks(ctx)
	a.maintainDirectAgents(ctx)
	a.loggedMaintenance(ctx, "订阅到期检查", a.expireSubscriptions)
	a.loggedMaintenance(ctx, "服务器流量账期检查", a.maintainMerchantBilling)
	a.loggedMaintenance(ctx, "共享服务器同步检查", a.refreshFederations)
	a.loggedMaintenance(ctx, "定时任务调度", a.maintainSchedules)
	a.loggedMaintenance(ctx, "证书与 DDNS 检查", a.maintainOperations)
	a.loggedMaintenance(ctx, "转发链状态检查", a.maintainForwardChains)
	a.subscriptionChangeEvents(ctx)
	a.subscriptionExpiryEvents(ctx, time.Now())
	a.maintainNotifications(ctx)
}
func (a *App) permitDispatch(ctx context.Context, task store.Task) bool {
	server, err := a.DB.GetRecord(ctx, "servers", task.ServerID)
	var cmd agentwire.Command
	switch {
	case err != nil || !nativeServer(server):
		task.Error = errUnsupportedServerConnection.Error()
	case retiredAgentAction(task.Kind):
		task.Error = "此动作已不受支持"
	case json.Unmarshal(task.Input, &cmd) != nil || retiredAgentAction(cmd.Action):
		task.Error = "任务指令无效或已不受支持"
	case !a.federationTaskPermitted(ctx, task):
		task.Error = "federation permission revoked before dispatch"
	default:
		if cmd.Action == "core.users.sync" {
			observation, err := a.DB.GetRecord(ctx, "_observations", task.ServerID)
			if err == nil {
				core, _ := observation.Data["core"].(map[string]any)
				if exists, reported := core["config_exists"].(bool); reported && !exists {
					return false // Wait for the initial configuration to be deployed.
				}
				if raw, reported := core["inbound_tags"]; reported {
					found := false
					for _, tag := range stringList(raw) {
						if tag == text(cmd.Params, "inbound") {
							found = true
							break
						}
					}
					if !found {
						return false
					}
				}
			}
		}
		if err := a.validateManagedInboundTask(ctx, task); err != nil {
			task.Error = err.Error()
		} else {
			return true
		}
	}
	task.Status = "failed"
	task.UpdatedAt = time.Now().UTC()
	_, _ = a.DB.SaveTask(ctx, task)
	return false
}
