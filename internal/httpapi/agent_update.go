package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

func (a *App) queueAgentUpdate(ctx context.Context, u store.User, id string, params map[string]any) (store.Task, error) {
	a.agentUpdateMu.Lock()
	defer a.agentUpdateMu.Unlock()
	version := text(params, "version")
	checksum := text(params, "sha256")
	rawURL := text(params, "url")
	if !regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`).MatchString(version) {
		return store.Task{}, errors.New("请选择明确的完整版本号")
	}
	digest, err := hex.DecodeString(checksum)
	if err != nil || len(digest) != 32 {
		return store.Task{}, errors.New("必须填写 64 位 SHA256 制品校验值")
	}
	address, err := url.Parse(rawURL)
	if err != nil || address.Host == "" || address.User != nil || address.Fragment != "" {
		return store.Task{}, errors.New("升级制品 URL 无效")
	}
	ip := net.ParseIP(address.Hostname())
	local := strings.EqualFold(address.Hostname(), "localhost") || ip != nil && ip.IsLoopback()
	if address.Scheme != "https" && !(address.Scheme == "http" && local) {
		return store.Task{}, errors.New("升级制品须为 HTTPS；仅本机测试允许 HTTP")
	}
	a.mu.Lock()
	peer := a.peers[id]
	supported := peer != nil && time.Since(peer.LastSeen) < 30*time.Second && peer.Capabilities["agent_update"]
	a.mu.Unlock()
	if !supported {
		return store.Task{}, errors.New("Agent 未在线或未启用可回滚升级监督进程，请先更新安装服务")
	}
	if observation, err := a.DB.GetRecord(ctx, "_observations", id); err == nil {
		state, _ := observation.Data["agent_update"].(map[string]any)
		switch text(state, "status") {
		case "staged", "ready", "restarting", "healthy":
			return store.Task{}, errors.New("Agent 正在完成上一轮升级确认")
		}
	}
	active, err := a.DB.HasActiveTask(ctx, id, "agent.update")
	if err != nil {
		return store.Task{}, err
	}
	if active {
		return store.Task{}, errors.New("已有升级任务待完成")
	}
	return a.queue(ctx, u, id, "agent.update", map[string]any{"url": rawURL, "version": version, "sha256": strings.ToLower(checksum)})
}
