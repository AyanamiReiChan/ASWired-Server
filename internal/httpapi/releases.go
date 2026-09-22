package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/AyanamiReiChan/ASWired-Server/internal/releases"
	"github.com/AyanamiReiChan/ASWired-Server/internal/selfupdate"
)

func (a *App) releaseLookup(ctx context.Context, preview bool) (releases.Info, error) {
	if a.resolveRelease != nil {
		return a.resolveRelease(ctx, preview)
	}
	return releases.Latest(ctx, preview)
}

func (a *App) updater() *selfupdate.Client {
	if a.updateClient != nil {
		return a.updateClient
	}
	return selfupdate.New(a.Config.DataDir, a.DB.Driver())
}

func (a *App) releaseUpdateStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]any{"current": Version, "updateStatus": a.updater().Status(r.Context())})
}

func (a *App) checkRelease(ctx context.Context, preview bool) (map[string]any, error) {
	info, err := a.releaseLookup(ctx, preview)
	if err != nil {
		return nil, err
	}
	available := releases.Newer(Version, info.Version)
	message := "当前已是最新版本（" + Version + "）"
	if available {
		message = "发现 " + info.Version + "，请查看发行说明并确认升级"
	}
	channel := "stable"
	if preview {
		channel = "prerelease"
	}
	return map[string]any{"current": Version, "version": info.Version, "available": available, "channel": channel, "url": info.URL, "agents": info.Agents, "message": message, "updateStatus": a.updater().Status(ctx)}, nil
}

func (a *App) requestReleaseUpdate(ctx context.Context, version string, preview bool) (map[string]any, error) {
	status := a.updater().Status(ctx)
	if !status.Supported {
		return nil, errors.New(status.Reason)
	}
	info, err := a.releaseLookup(ctx, preview)
	if err != nil {
		return nil, err
	}
	if version != info.Version {
		return nil, errors.New("可用版本已经变化，请重新检查并确认目标版本")
	}
	if !releases.Newer(Version, version) {
		return nil, errors.New("目标版本必须高于当前版本")
	}
	if err = a.updater().Request(ctx, version); err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "version": version, "message": "升级请求已提交，正在等待更新服务；请查看进度", "updateStatus": a.updater().Status(ctx)}, nil
}
