package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) scanRealityAgent(ctx context.Context, user store.User, serverID string, targets []realityScanTarget) ([]realityScanResult, error) {
	server, err := a.DB.GetRecord(ctx, "servers", serverID)
	if err != nil || !nativeServer(server) || disabledStatus(server.Data) {
		return nil, errors.New("请选择可用的 ASWired Agent 服务器")
	}
	a.mu.Lock()
	p := a.peers[serverID]
	ready := p != nil && time.Since(p.LastSeen) < 45*time.Second && p.Capabilities["reality_scan"]
	a.mu.Unlock()
	if !ready {
		return nil, errors.New("Agent 离线或尚不支持 REALITY 扫描，请更新 Agent 后重试")
	}
	addresses := make([]string, len(targets))
	for i, target := range targets {
		addresses[i] = target.address
	}
	deadline, _ := ctx.Deadline()
	task, err := a.queue(ctx, user, serverID, "reality.scan", map[string]any{"targets": strings.Join(addresses, "\n"), "expiresAt": deadline.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("扫描等待已结束：%w；Agent 已收到的任务可能仍在完成，结果不会加入目标池", ctx.Err())
		case <-ticker.C:
		}
		current, err := a.DB.GetTask(ctx, task.ID)
		if err != nil {
			return nil, err
		}
		switch current.Status {
		case "queued", "running":
			continue
		case "success":
			return decodeAgentRealityResults(current.Result, targets, server)
		default:
			return nil, fmt.Errorf("Agent 扫描失败（%s）：%s", current.Status, current.Error)
		}
	}
}

func decodeAgentRealityResults(raw []byte, targets []realityScanTarget, server store.Record) ([]realityScanResult, error) {
	var data struct {
		Results []realityScanResult `json:"results"`
	}
	if len(raw) > 4<<20 || json.Unmarshal(raw, &data) != nil || len(data.Results) != len(targets) {
		return nil, errors.New("Agent 返回的扫描结果不完整")
	}
	expected := map[string]bool{}
	for _, target := range targets {
		expected[target.address] = true
	}
	seen := map[string]bool{}
	for i := range data.Results {
		result := &data.Results[i]
		target, err := parseRealityScanTarget(result.Target)
		if err != nil || !expected[target.address] || seen[target.address] || result.Port != target.port {
			return nil, errors.New("Agent 扫描结果与请求目标不一致")
		}
		seen[target.address] = true
		if !target.isIP && result.Host != target.host {
			return nil, errors.New("Agent 返回了不同的 SNI 域名")
		}
		checked := dateTime(result.CheckedAt)
		age := time.Since(checked)
		if checked.IsZero() || age < -90*time.Second || age > 2*time.Minute {
			return nil, errors.New("Agent 扫描证据已过期或时间无效")
		}
		result.ID = newID()
		result.Source = "agent"
		result.ServerID = server.ID
		result.ServerName = text(server.Data, "name")
		// Use receipt time for the controller's import window; Agent clock skew has
		// already been bounded above and by the authenticated report envelope.
		result.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return data.Results, nil
}
