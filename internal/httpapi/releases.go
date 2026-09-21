package httpapi

import (
	"context"
	"github.com/AyanamiReiChan/ASWired-Server/internal/releases"
)

func (a *App) checkRelease(ctx context.Context, preview bool) (map[string]any, error) {
	info, err := releases.Latest(ctx, preview)
	if err != nil {
		return nil, err
	}
	available := releases.Newer(Version, info.Version)
	message := "当前已是最新版本（" + Version + "）"
	if available {
		message = "发现 " + info.Version + "，请查看发行说明并使用部署目录的 update.sh 升级"
	}
	channel := "stable"
	if preview {
		channel = "prerelease"
	}
	return map[string]any{"current": Version, "version": info.Version, "available": available, "channel": channel, "url": info.URL, "agents": info.Agents, "message": message}, nil
}
