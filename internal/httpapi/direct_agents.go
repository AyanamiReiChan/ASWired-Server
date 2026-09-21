package httpapi

import (
	"context"
	"encoding/json"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"sort"
	"time"
)

func (a *App) maintainDirectAgents(ctx context.Context) {
	servers, e := a.DB.ListRecords(ctx, "servers", "")
	if e != nil {
		return
	}
	attempts, e := a.DB.ListRecords(ctx, "_directPoll", "")
	if e != nil {
		return
	}
	last := map[string]time.Time{}
	for _, row := range attempts {
		last[row.ID] = dateTime(text(row.Data, "at"))
	}
	sort.SliceStable(servers, func(i, j int) bool { return last[servers[i].ID].Before(last[servers[j].ID]) })
	for _, server := range servers {
		if !a.shouldContactDirect(server) {
			continue
		}
		server := server
		a.startJob(ctx, "direct:"+server.ID, func(ctx context.Context) {
			old, _ := a.DB.GetRecord(ctx, "_directPoll", server.ID)
			if _, e := a.DB.SaveRecord(ctx, store.Record{Collection: "_directPoll", ID: server.ID, Version: old.Version, Data: map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano)}}); e != nil {
				return
			}
			a.pollDirectAgent(ctx, server)
		})
	}
}
func (a *App) pollDirectAgent(ctx context.Context, server store.Record) {
	fresh, e := a.DB.GetRecord(ctx, "servers", server.ID)
	if e != nil || !a.shouldContactDirect(fresh) {
		return
	}
	server = fresh
	params := map[string]any{"connection_mode": serverConnectionMode(server), "listen_address": agentListenAddress(server)}
	if observation, err := a.DB.GetRecord(ctx, "_observations", server.ID); err == nil {
		update, _ := observation.Data["agent_update"].(map[string]any)
		if task, err := a.DB.GetTask(ctx, text(update, "taskId")); err == nil && task.ServerID == server.ID && task.Kind == "agent.update" && task.Status == "success" {
			params["acknowledged_update"] = task.ID
		}
	}
	result, e := a.direct(ctx, server, agentwire.Command{ID: newID(), Action: "agent.report", Params: params})
	if e != nil || result.Status != "success" {
		return
	}
	credentials, e := a.DB.GetRecord(ctx, "_agentCredentials", server.ID)
	if e != nil {
		return
	}
	observation, _ := result.Data["observation"].(map[string]any)
	caps := map[string]bool{}
	if m, ok := result.Data["capabilities"].(map[string]any); ok {
		for k, v := range m {
			caps[k] = v == true
		}
	}
	_, e = a.acceptReport(ctx, agentwire.Report{ServerID: server.ID, Token: text(credentials.Data, "serverToken"), Version: text(result.Data, "version"), Mode: text(result.Data, "mode"), ConnectionMode: text(result.Data, "connection_mode"), Observation: observation, Capabilities: caps, Timestamp: time.Now().Unix()}, "HTTP")
	if e != nil {
		return
	}
	if changed, _ := result.Data["connection_changed"].(bool); changed {
		return
	}
	if mode := serverConnectionMode(server); mode != "auto" && mode != "http" {
		return
	}
	commands, e := a.DB.ListPendingTasks(ctx, server.ID, 4)
	if e != nil {
		return
	}
	for _, task := range commands {
		// Recheck after acquiring the shared dispatch lock: a simultaneous
		// Pull report may already have claimed this task.
		a.agentDispatchMu.Lock()
		current, err := a.DB.GetTask(ctx, task.ID)
		if err != nil || current.Status != "queued" {
			a.agentDispatchMu.Unlock()
			continue
		}
		task = current
		if ctx.Err() != nil {
			a.agentDispatchMu.Unlock()
			return
		}
		fresh, e := a.DB.GetRecord(ctx, "servers", server.ID)
		if e != nil || !a.shouldContactDirect(fresh) || (serverConnectionMode(fresh) != "auto" && serverConnectionMode(fresh) != "http") {
			a.agentDispatchMu.Unlock()
			return
		}
		server = fresh
		if !a.permitDispatch(ctx, task) {
			a.agentDispatchMu.Unlock()
			continue
		}
		var cmd agentwire.Command
		if json.Unmarshal(task.Input, &cmd) != nil {
			a.agentDispatchMu.Unlock()
			continue
		}
		task.Status = "running"
		task.UpdatedAt = time.Now()
		if _, e = a.DB.SaveTask(ctx, task); e != nil {
			a.agentDispatchMu.Unlock()
			continue
		}
		a.agentDispatchMu.Unlock()
		result, e := a.direct(ctx, server, cmd)
		if e != nil {
			task.Status, task.Error, task.UpdatedAt = "unknown", "HTTP 结果未确认："+e.Error(), time.Now()
			_, _ = a.DB.SaveTask(ctx, task)
			continue
		}
		a.finishTask(ctx, server.ID, result)
	}
}

func (a *App) shouldContactDirect(server store.Record) bool {
	if disabledStatus(server.Data) || !nativeServer(server) {
		return false
	}
	a.mu.Lock()
	p := a.peers[server.ID]
	activeWS := p != nil && p.Transport == "WebSocket" && time.Since(p.LastSeen) < 15*time.Second
	wasHTTP := p != nil && p.Transport == "HTTP"
	a.mu.Unlock()
	mode := serverConnectionMode(server)
	return !activeWS && (mode == "http" || mode == "auto" || wasHTTP)
}
