package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
	"github.com/AyanamiReiChan/ASWired-Server/pkg/agentwire"
	"net/http"
	"strings"
	"time"
)

func (a *App) homeEnrollment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, e := a.DB.GetRecord(r.Context(), "endpoints", id); e != nil {
		fail(w, 404, "not_found", "测速端不存在")
		return
	}
	cred, e := a.DB.GetRecord(r.Context(), "_homeCredentials", id)
	if errors.Is(e, store.ErrNotFound) {
		cred, e = a.DB.SaveRecord(r.Context(), store.Record{Collection: "_homeCredentials", ID: id, Data: map[string]any{"serverToken": newID() + newID(), "agentToken": newID() + newID()}})
	}
	if e != nil {
		fail(w, 500, "storage_error", "配对凭据创建失败")
		return
	}
	respond(w, 200, map[string]any{"config": map[string]any{"role": "speedtest", "mode": "remote", "server_id": id, "token": cred.Data["serverToken"], "agent_token": cred.Data["agentToken"], "master_url": strings.TrimRight(a.Config.PublicURL, "/"), "master_public_key": a.MasterPublic, "connection_mode": "websocket", "data_dir": "./home-data"}})
}
func (a *App) acceptHomeReport(ctx context.Context, report agentwire.Report, transport string) (agentwire.Reply, error) {
	if transport != "WebSocket" {
		return agentwire.Reply{}, errors.New("only WebSocket is supported")
	}
	cred, e := a.DB.GetRecord(ctx, "_homeCredentials", report.ServerID)
	if e != nil || !homeTokenAccepted(cred, report.Token, time.Now()) {
		return agentwire.Reply{}, errors.New("speedtest identity rejected")
	}
	endpoint, e := a.DB.GetRecord(ctx, "endpoints", report.ServerID)
	if e != nil {
		return agentwire.Reply{}, e
	}
	if text(endpoint.Data, "status") == "禁用" {
		return agentwire.Reply{}, errors.New("speedtest endpoint disabled")
	}
	a.mu.Lock()
	a.peers[report.ServerID] = &peer{LastSeen: time.Now(), Transport: transport, Version: report.Version, Mode: "speedtest", Capabilities: report.Capabilities}
	a.mu.Unlock()
	// Only publish source metadata reported by the paired runner.
	observation, _ := a.DB.GetRecord(ctx, "_homeObservations", report.ServerID)
	_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "_homeObservations", ID: report.ServerID, Version: observation.Version, Data: map[string]any{"sourceMode": report.Observation["source_mode"], "platform": report.Observation["platform"]}})
	for _, result := range report.Results {
		task, e := a.DB.GetTask(ctx, result.ID)
		if e != nil || task.ServerID != report.ServerID || (task.Kind != "speedtest.run" && task.Kind != "source.fetch" && task.Kind != "identity.rotate") {
			continue
		}
		if !a.finishTask(ctx, report.ServerID, result) {
			continue
		}
		if task.Kind == "speedtest.run" {
			data := clone(result.Data)
			if data == nil {
				data = map[string]any{}
			}
			data["status"], data["error"] = result.Status, result.Error
			var command agentwire.Command
			if json.Unmarshal(task.Input, &command) == nil {
				for _, key := range []string{"nodeId", "nodeName", "subscriptionId", "parallel", "latency_only"} {
					data[key] = command.Params[key]
				}
				data["download_limit_bytes"] = command.Params["download_bytes"]
			}
			data["endpointId"] = report.ServerID
			data["testedAt"] = time.Now().UTC()
			previous, _ := a.DB.GetRecord(ctx, "speedtests", result.ID)
			_, _ = a.DB.SaveRecord(ctx, store.Record{Collection: "speedtests", ID: result.ID, Version: previous.Version, OwnerID: task.ActorID, Data: data})
		}
	}
	tasks, e := a.DB.ListPendingTasks(ctx, report.ServerID, 30)
	if e != nil {
		return agentwire.Reply{}, e
	}
	commands := []agentwire.Command{}
	for _, task := range tasks {
		if task.Status != "queued" || (task.Kind != "speedtest.run" && task.Kind != "source.fetch" && task.Kind != "identity.rotate") {
			continue
		}
		var cmd agentwire.Command
		if json.Unmarshal(task.Input, &cmd) != nil {
			continue
		}
		if cmd.Action == "speedtest.run" {
			node, _ := cmd.Params["node"].(map[string]any)
			if _, err := normalizedProxyNode(node, true); err != nil {
				task.Status = "failed"
				task.Error = err.Error()
				task.UpdatedAt = time.Now()
				_, _ = a.DB.SaveTask(ctx, task)
				continue
			}
		}
		task.Status = "running"
		task.UpdatedAt = time.Now()
		if _, e = a.DB.SaveTask(ctx, task); e != nil {
			continue
		}
		commands = append(commands, cmd)
		break
	}
	return agentwire.Reply{Commands: commands, Interval: 5}, nil
}
func (a *App) queueHome(ctx context.Context, u store.User, id string, params map[string]any) (store.Task, error) {
	if _, e := a.DB.GetRecord(ctx, "endpoints", id); e != nil {
		return store.Task{}, e
	}
	if number(params, "download_bytes") > 0 || boolean(params, "latency_only") || number(params, "parallel") > 8 {
		a.mu.Lock()
		p := a.peers[id]
		ready := p != nil && time.Since(p.LastSeen) < 45*time.Second && p.Capabilities["speedtest_bounded"]
		a.mu.Unlock()
		if !ready {
			return store.Task{}, errors.New("请连接支持限量下载的新版本测速端后重试")
		}
	}
	node, ok := params["node"].(map[string]any)
	if !ok {
		return store.Task{}, errors.New("测速须提供Clash节点对象")
	}
	normalized, err := normalizedProxyNode(node, true)
	if err != nil {
		return store.Task{}, err
	}
	client, err := clientNodeFor(store.Record{Data: normalized}, store.Record{})
	if err != nil {
		return store.Task{}, err
	}
	params = clone(params)
	params["node"] = clashNode(client)
	cmd := agentwire.Command{ID: newID(), Action: "speedtest.run", Params: params}
	raw, _ := json.Marshal(cmd)
	return a.DB.SaveTask(ctx, store.Task{ID: cmd.ID, ServerID: id, ActorID: u.ID, Kind: cmd.Action, Status: "queued", Input: raw, CreatedAt: time.Now(), UpdatedAt: time.Now()})
}
