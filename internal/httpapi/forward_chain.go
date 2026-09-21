package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) beginForwardChain(ctx context.Context, user store.User, id string) (map[string]any, error) {
	group, e := a.DB.GetRecord(ctx, "forwards", id)
	if e != nil {
		return nil, e
	}
	hops, _ := group.Data["hops"].([]any)
	if len(hops) < 2 || len(hops) > 8 {
		return nil, errors.New("转发链需要2至8个跳点")
	}
	protocol := defaultText(group.Data, "protocol", "tcp")
	if protocol != "tcp" && protocol != "udp" {
		return nil, errors.New("转发链协议仅支持tcp或udp")
	}
	target := text(group.Data, "target")
	if e = validateForwardAddress(target, false); e != nil {
		return nil, e
	}
	previous, _ := a.DB.GetRecord(ctx, "_forwardChains", id)
	if text(previous.Data, "status") == "waiting" || text(previous.Data, "status") == "dispatching" {
		return nil, errors.New("转发链正在发布，请先等待实际结果")
	}
	seen := map[string]bool{}
	children := []store.Record{}
	order := []any{}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := hops[i].(map[string]any)
		if !ok {
			return nil, errors.New("跳点须为对象")
		}
		serverID := text(hop, "serverId")
		if seen[serverID] {
			return nil, errors.New("转发链不允许重复服务器")
		}
		seen[serverID] = true
		server, e := a.DB.GetRecord(ctx, "servers", serverID)
		if e != nil {
			return nil, e
		}
		if !nativeServer(server) {
			return nil, errUnsupportedServerConnection
		}
		listen := text(hop, "listen")
		if e = validateForwardAddress(listen, true); e != nil {
			return nil, e
		}
		_, port, _ := net.SplitHostPort(listen)
		host := strings.Trim(defaultText(server.Data, "publicAddress", text(server.Data, "address")), "[]")
		if strings.ContainsAny(host, "/\\?#@ ") || host == "" {
			return nil, errors.New("跳点对外地址无效")
		}
		childID := id + "-hop-" + strconv.Itoa(i)
		old, _ := a.DB.GetRecord(ctx, "forwards", childID)
		if old.ID != "" && text(old.Data, "chainId") != id {
			return nil, errors.New("跳点标识与其他转发冲突")
		}
		children = append(children, store.Record{Collection: "forwards", ID: childID, Version: old.Version, Data: map[string]any{"name": text(group.Data, "name") + " · " + strconv.Itoa(i+1), "serverId": serverID, "chainId": id, "status": "禁用", "rules": []any{map[string]any{"protocol": protocol, "listen": listen, "target": target}}}})
		order = append(order, childID)
		target = net.JoinHostPort(host, port)
	}

	state := store.Record{Collection: "_forwardChains", ID: id, OwnerID: user.ID, Version: previous.Version, Data: map[string]any{"status": "ready", "order": order, "next": 0, "taskIds": []any{}, "revision": newID(), "startedAt": time.Now().UTC().Format(time.RFC3339Nano)}}
	saved, e := a.DB.CompareAndSaveRecords(ctx, append(children, state))
	if e != nil {
		return nil, e
	}
	state = saved[len(saved)-1]
	a.advanceForwardChain(ctx, state)
	state, e = a.DB.GetRecord(ctx, "_forwardChains", id)
	if e != nil {
		return nil, e
	}
	return map[string]any{"chain": rowOf(state, false), "message": "从终点逐跳发布；下游成功监听后才开放上一跳。任务结果保存在转发链状态。"}, nil
}
func validateForwardAddress(value string, listen bool) error {
	host, port, e := net.SplitHostPort(value)
	if e != nil {
		return errors.New("转发地址须为host:port")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("转发端口须为1至65535")
	}
	if listen && net.ParseIP(host) == nil {
		return errors.New("监听地址须为明确IPv4或IPv6地址")
	}
	if !listen && (host == "" || strings.ContainsAny(host, "/\\?#@ ")) {
		return errors.New("转发目标地址无效")
	}
	return nil
}
func (a *App) maintainForwardChains(ctx context.Context) {
	rows, e := a.DB.ListRecords(ctx, "_forwardChains", "")
	if e != nil {
		return
	}
	for _, row := range rows {
		a.advanceForwardChain(ctx, row)
	}
}
func (a *App) advanceForwardChain(ctx context.Context, state store.Record) {
	status := text(state.Data, "status")
	if status != "ready" && status != "waiting" && status != "dispatching" {
		return
	}
	failChain := func(message string) {
		state.Data["status"] = "failed"
		state.Data["error"] = message
		_, _ = a.DB.SaveRecord(ctx, state)
	}
	if status == "dispatching" {
		if time.Since(state.UpdatedAt) > time.Minute {
			failChain("发布过程被中断，上一跳未开放；请核对任务和节点后重新发布")
		}
		return
	}
	if status == "waiting" {
		task, e := a.DB.GetTask(ctx, text(state.Data, "currentTaskId"))
		if e != nil {
			return
		}
		switch task.Status {
		case "queued", "running":
			return
		case "success":
			state.Data["next"] = number(state.Data, "next") + 1
		default:
			failChain("下游任务 " + task.ID + " 未成功，已停止继续开放入口")
			return
		}
	}
	order := stringList(state.Data["order"])
	next := int(number(state.Data, "next"))
	if next >= len(order) {
		state.Data["status"] = "success"
		state.Data["finishedAt"] = time.Now().UTC()
		_, _ = a.DB.SaveRecord(ctx, state)
		return
	}
	state.Data["status"] = "dispatching"
	claimed, e := a.DB.SaveRecord(ctx, state)
	if e != nil {
		return
	}
	state = claimed
	user, e := a.DB.UserByID(ctx, state.OwnerID)
	if e != nil || user.Disabled || user.Role != "admin" {
		failChain("发布账户已失效或失去管理员权限")
		return
	}
	child, e := a.DB.GetRecord(ctx, "forwards", order[next])
	if e != nil {
		failChain(fmt.Sprint(e))
		return
	}
	child.Data["status"] = "启用"
	if _, e = a.DB.SaveRecord(ctx, child); e != nil {
		failChain(fmt.Sprint(e))
		return
	}
	_, out, e := a.networkAction(ctx, user, actionInput{Action: "forward.apply", TargetID: order[next]})
	if e != nil {
		failChain(fmt.Sprint(e))
		return
	}
	task, _ := out["task"].(map[string]any)
	taskID := text(task, "id")
	if taskID == "" {
		failChain("下游任务未建立")
		return
	}
	ids := stringList(state.Data["taskIds"])
	ids = append(ids, taskID)
	state.Data["taskIds"] = ids
	state.Data["currentTaskId"] = taskID
	state.Data["status"] = "waiting"
	_, _ = a.DB.SaveRecord(ctx, state)
}
