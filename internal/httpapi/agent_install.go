package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AyanamiReiChan/ASWired-Server/internal/store"
)

//go:embed agent_install.sh
var agentInstallScript string

func (a *App) agentInstallConfig(server store.Record, credentials store.Record) map[string]any {
	return map[string]any{"master_url": strings.TrimRight(a.Config.PublicURL, "/"), "server_id": server.ID, "token": text(credentials.Data, "serverToken"), "agent_token": text(credentials.Data, "agentToken"), "master_public_key": a.MasterPublic, "connection_mode": serverConnectionMode(server), "listen_address": agentListenAddress(server), "xray_mode": "embedded", "data_dir": "/var/lib/aswired-agent"}
}

// Tickets grant only this server's installer and binaries, expire in 30 minutes,
// and become invalid when credentials rotate or the server is removed/disabled.
func (a *App) installTicket(id, expires string, credentials store.Record) string {
	mac := hmac.New(sha256.New, a.Config.JWTSecret)
	for _, part := range []string{"agent-install-v1", id, expires, text(credentials.Data, "serverToken"), text(credentials.Data, "agentToken")} {
		fmt.Fprintf(mac, "%d:%s", len(part), part)
	}
	return expires + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func (a *App) agentArtifact(arch string) string {
	return filepath.Join(a.Config.DataDir, "agent-releases", "linux-"+arch, "aswired-agent")
}

func (a *App) artifactHash(arch string) string {
	f, err := os.Open(a.agentArtifact(arch))
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return ""
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a *App) installationOffer(server, credentials store.Record) map[string]any {
	arches := []string{}
	for _, arch := range []string{"amd64", "arm64"} {
		if a.artifactHash(arch) != "" {
			arches = append(arches, arch)
		}
	}
	offer := map[string]any{"available": false, "platforms": arches, "note": "主控尚未配置 Linux Agent 安装包，请管理员按部署文档放入安装包后重新生成。"}
	if disabledStatus(server.Data) {
		offer["note"] = "请先启用服务器，再生成安装命令。"
		return offer
	}
	if len(arches) == 0 {
		return offer
	}
	expires := time.Now().Add(30 * time.Minute).Unix()
	ticket := a.installTicket(server.ID, strconv.FormatInt(expires, 10), credentials)
	scriptURL := strings.TrimRight(a.Config.PublicURL, "/") + "/api/agent/install/" + url.PathEscape(server.ID) + "/install.sh?ticket=" + url.QueryEscape(ticket)
	// Download fully before execution; a broken download must never run a partial script.
	command := "(umask 077; f=$(mktemp) || exit 1; trap 'rm -f \"$f\"' EXIT HUP INT TERM; curl -fSsL --proto '=http,https' --proto-redir '=https' " + shellQuote(scriptURL) + " -o \"$f\" && sh \"$f\")"
	u, _ := url.Parse(a.Config.PublicURL)
	local := u != nil && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")
	return map[string]any{"available": true, "platforms": arches, "command": command, "expiresAt": time.Unix(expires, 0).UTC(), "localOnly": local, "note": "在目标服务器以 root 执行，支持 Linux systemd，自动识别架构；安装后等待 Agent 上报。"}
}

func (a *App) agentInstallDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	id := r.PathValue("id")
	parts := strings.Split(r.URL.Query().Get("ticket"), ".")
	if len(parts) != 2 {
		fail(w, 403, "invalid_install_ticket", "安装命令无效或已过期，请重新生成")
		return
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expires <= time.Now().Unix() || expires > time.Now().Add(31*time.Minute).Unix() {
		fail(w, 403, "invalid_install_ticket", "安装命令无效或已过期，请重新生成")
		return
	}
	credentials, err := a.DB.GetRecord(r.Context(), "_agentCredentials", id)
	if err != nil || !constant(r.URL.Query().Get("ticket"), a.installTicket(id, parts[0], credentials)) {
		fail(w, 403, "invalid_install_ticket", "安装命令无效或已过期，请重新生成")
		return
	}
	server, err := a.DB.GetRecord(r.Context(), "servers", id)
	if err != nil || !nativeServer(server) || disabledStatus(server.Data) || (text(server.Data, "xray_mode") != "" && text(server.Data, "xray_mode") != "embedded") {
		fail(w, 403, "invalid_install_target", "服务器不可接入")
		return
	}
	file := r.PathValue("file")
	if file == "linux-amd64" || file == "linux-arm64" {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, a.agentArtifact(strings.TrimPrefix(file, "linux-")))
		return
	}
	if file != "install.sh" {
		fail(w, 404, "not_found", "安装文件不存在")
		return
	}
	cfg, _ := json.Marshal(a.agentInstallConfig(server, credentials))
	base := strings.TrimRight(a.Config.PublicURL, "/") + "/api/agent/install/" + url.PathEscape(id)
	script := strings.NewReplacer("@@CONFIG@@", base64.StdEncoding.EncodeToString(cfg), "@@AMD64@@", shellQuote(a.artifactHash("amd64")), "@@ARM64@@", shellQuote(a.artifactHash("arm64")), "@@BASE@@", shellQuote(base), "@@TICKET@@", shellQuote(r.URL.Query().Get("ticket"))).Replace(agentInstallScript)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = io.WriteString(w, script)
}
